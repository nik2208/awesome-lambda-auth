package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
	"github.com/nik2208/awesome-lambda-auth/internal/store/migrating"
)

// cognitoFlags is the subcommand's whole surface. It is a struct rather than a
// pile of locals so that the dry-run summary can print the configuration it was
// about to act on, which is half of what makes a dry run worth running.
type cognitoFlags struct {
	userPoolID   string
	table        string
	region       string
	tableRegion  string
	profile      string
	endpoint     string
	tenantID     string
	attributeMap string
	startToken   string
	pageSize     int
	dryRun       bool
	multiTenant  bool
}

func runCognito(ctx context.Context, args []string, stdout, stderr *os.File) error {
	var f cognitoFlags
	fs := flag.NewFlagSet("migrate cognito", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.StringVar(&f.userPoolID, "user-pool-id", "", "the Cognito user pool to read, e.g. <region>_XXXXXXXXX (required)")
	fs.StringVar(&f.table, "table", "", "the DynamoDB single table to write, i.e. stores.connection.tableName (required)")
	fs.StringVar(&f.region, "region", "", "the region the user pool lives in (required)")
	fs.StringVar(&f.tableRegion, "table-region", "", "the region the table lives in; defaults to --region")
	fs.StringVar(&f.profile, "profile", "", "a profile in the shared AWS config file; empty uses the default credential chain")
	fs.StringVar(&f.endpoint, "endpoint", "", "override the DynamoDB endpoint, for DynamoDB Local")
	fs.StringVar(&f.tenantID, "tenant", "", "the tenant id every imported row is written under; empty is the single-tenant default")
	fs.StringVar(&f.attributeMap, "attribute-map", "", "a JSON file mapping source attribute names onto fields")
	fs.StringVar(&f.startToken, "start-token", "", "resume from the pagination token an interrupted run printed")
	fs.IntVar(&f.pageSize, "page-size", 60, "users per ListUsers call (1-60)")
	fs.BoolVar(&f.dryRun, "dry-run", false, "report exactly what would be written and write nothing")
	fs.BoolVar(&f.multiTenant, "multi-tenant", false, "refuse an empty tenant id at the store boundary, matching stores' MultiTenant option")

	fs.Usage = func() {
		fmt.Fprint(stderr, "migrate cognito imports users from an Amazon Cognito user pool.\n\n"+
			"Passwords are NOT imported: a user pool yields no password hash. Each row lands\n"+
			"with an empty passwordHash and a migration marker, and the password is collected\n"+
			"on the person's next login through the password-verifier seam.\n\n"+
			"flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return flagError(err)
	}

	missing := make([]string, 0, 3)
	if strings.TrimSpace(f.userPoolID) == "" {
		missing = append(missing, "--user-pool-id")
	}
	if strings.TrimSpace(f.table) == "" {
		missing = append(missing, "--table")
	}
	if strings.TrimSpace(f.region) == "" {
		// Demanded rather than inherited from the ambient AWS_REGION, for the
		// reason RS-13 demands it of the deployment: a pool addressed in the
		// wrong region answers "no such user" for every person, and a bulk
		// import against the wrong region is an empty run that looks successful.
		missing = append(missing, "--region")
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "migrate cognito: missing required flag(s): %s\n\n", strings.Join(missing, ", "))
		fs.Usage()
		return errReported
	}
	if f.pageSize < 1 || f.pageSize > 60 {
		fmt.Fprintf(stderr, "migrate cognito: --page-size %d is outside Cognito's own 1-60 range for ListUsers\n", f.pageSize)
		return errReported
	}

	attrs := migrating.DefaultAttributeMap()
	if f.attributeMap != "" {
		loaded, err := loadAttributeMap(f.attributeMap)
		if err != nil {
			fmt.Fprintf(stderr, "migrate cognito: %v\n", err)
			return errReported
		}
		attrs = loaded
	}
	// Validated before the first page is read: a typo in a map file must be a
	// refusal, not four thousand users imported without a phone number.
	if err := attrs.Validate(); err != nil {
		fmt.Fprintf(stderr, "migrate cognito: %v\n", err)
		return errReported
	}

	directory, err := awsintegration.NewCognitoDirectory(awsintegration.CognitoOptions{
		UserPoolID: f.userPoolID,
		Region:     f.region,
		Profile:    f.profile,
		// No ClientID: this command never signs anybody in, and an app client it
		// does not hold is an app client it cannot accidentally use.
	})
	if err != nil {
		fmt.Fprintf(stderr, "migrate cognito: %v\n", err)
		return errReported
	}

	var store userWriter = dryRunWriter{out: stdout}
	if !f.dryRun {
		real, err := openStore(ctx, f)
		if err != nil {
			fmt.Fprintf(stderr, "migrate cognito: %v\n", err)
			return errReported
		}
		store = real
	}

	return importAll(ctx, importOptions{
		flags:     f,
		directory: directory,
		store:     store,
		attrs:     attrs,
		ref: migrating.SourceRef{
			Source: config.MigrationSourceCognito,
			Pool:   strings.TrimSpace(f.userPoolID),
		},
		stdout: stdout,
		stderr: stderr,
	})
}

// userWriter is the one store method this command calls. Narrow on purpose: the
// dry run is a complete implementation of it, which is what makes "--dry-run
// reports exactly what it would write" true by construction rather than by two
// code paths that are meant to agree.
//
// The marker is a separate argument and not a field on the user, because it is
// one everywhere: it never rides on auth.User, in either direction, which is
// what keeps it off GET /me (internal/store/dynamodb/migration.go).
type userWriter interface {
	CreateMigratedUser(ctx context.Context, user auth.User, marker ddbstore.MigrationMarker) (auth.User, error)
}

// dryRunWriter is the whole of --dry-run. It receives the same fully built
// auth.User and the same marker the real store would receive, prints them, and
// answers as a successful write — so every decision above it, including the
// attribute mapping and the skip rules, is exercised exactly as it would be in a
// real run.
type dryRunWriter struct{ out *os.File }

func (w dryRunWriter) CreateMigratedUser(_ context.Context, user auth.User, marker ddbstore.MigrationMarker) (auth.User, error) {
	fmt.Fprintf(w.out, "would create %s <%s>%s%s migration{source=%s,pool=%s}%s\n",
		user.ID, user.Email,
		describeIf(user.IsEmailVerified, " emailVerified"),
		describeIf(user.PhoneNumber != "", " phone"),
		marker.Source, marker.Pool,
		describeMetadata(user.Metadata))
	return user, nil
}

func describeIf(cond bool, s string) string {
	if cond {
		return s
	}
	return ""
}

// describeMetadata renders the imported attributes, sorted, so a dry run's
// output is stable enough to diff between two runs. The marker is not in here:
// it is not in Metadata, which is the point.
func describeMetadata(md map[string]any) string {
	if len(md) == 0 {
		return ""
	}
	var b strings.Builder
	for _, key := range []string{ddbstore.ImportedAttributesKey} {
		raw, ok := md[key].(map[string]any)
		if !ok || len(raw) == 0 {
			continue
		}
		names := make([]string, 0, len(raw))
		for k := range raw {
			names = append(names, k)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, n := range names {
			parts = append(parts, fmt.Sprintf("%s=%v", n, raw[n]))
		}
		fmt.Fprintf(&b, " %s{%s}", key, strings.Join(parts, ","))
	}
	return b.String()
}

// openStore builds the real DynamoDB store.
//
// The table region defaults to the pool's, which is right for the common case
// and wrong for the interesting one: migrating out of an old account usually
// means the pool and the table are in different places, which is what
// --table-region is for.
func openStore(ctx context.Context, f cognitoFlags) (*ddbstore.Store, error) {
	region := f.tableRegion
	if region == "" {
		region = f.region
	}
	client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{
		Region:   region,
		Endpoint: f.endpoint,
		Profile:  f.profile,
	})
	if err != nil {
		return nil, err
	}
	return ddbstore.New(client, ddbstore.Options{
		TableName:   f.table,
		MultiTenant: f.multiTenant,
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
}

// loadAttributeMap reads the --attribute-map file: a flat JSON object from
// source attribute name to target field.
//
//	{"custom:department": "metadata:department", "custom:role": "role", "locale": "-"}
//
// Flat and not nested, because every entry answers the same question about one
// attribute and a nesting would only be somewhere to hide a typo.
func loadAttributeMap(path string) (migrating.AttributeMap, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read --attribute-map %s: %w", path, err)
	}
	var m migrating.AttributeMap
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("--attribute-map %s is not a flat JSON object of string to string: %w", path, err)
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("--attribute-map %s is empty; omit the flag to use the default mapping", path)
	}
	return m, nil
}

type importOptions struct {
	flags     cognitoFlags
	directory awsintegration.CognitoDirectory
	store     userWriter
	attrs     migrating.AttributeMap
	ref       migrating.SourceRef
	stdout    *os.File
	stderr    *os.File
}

// tally is the summary. Every counter here is one of the decisions the package
// comment promises to have made explicitly.
type tally struct {
	read     int
	written  int
	existing int
	noEmail  []string
	failed   []string
}

// importAll pages the pool and imports every user.
//
// One page at a time, and the page is fully processed before the next is asked
// for. The alternative — reading every page first, then writing — would double
// the window in which an interruption loses work and would hold a whole pool in
// memory for no gain, since the write is the slow half either way.
func importAll(ctx context.Context, o importOptions) error {
	var t tally
	token := o.flags.startToken
	// resumeToken is the token of the last page that was fully processed. It is
	// what an interrupted run prints, and it deliberately lags `token`: printing
	// the token of a page that was only half written would skip the other half.
	resumeToken := o.flags.startToken

	if o.flags.dryRun {
		fmt.Fprintf(o.stdout, "dry run: pool %s -> table %s, nothing will be written\n", o.flags.userPoolID, o.flags.table)
	}

	for {
		if err := ctx.Err(); err != nil {
			// An interruption, not a failure. The summary and the resume token
			// are worth more than a stack trace.
			fmt.Fprintf(o.stderr, "migrate cognito: interrupted\n")
			reportTally(o.stdout, o.stderr, t, resumeToken)
			return errReported
		}

		page, err := o.directory.ListUsers(ctx, token, int32(o.flags.pageSize))
		if err != nil {
			fmt.Fprintf(o.stderr, "migrate cognito: reading the pool failed: %v\n", err)
			reportTally(o.stdout, o.stderr, t, resumeToken)
			return errReported
		}

		for _, rec := range page.Users {
			t.read++
			importUser(ctx, o, rec, &t)
		}

		resumeToken = page.NextToken
		if page.NextToken == "" {
			break
		}
		token = page.NextToken
	}

	reportTally(o.stdout, o.stderr, t, "")
	if len(t.noEmail) > 0 || len(t.failed) > 0 {
		return errReported
	}
	return nil
}

// importUser imports one record, recording which of the four outcomes it was.
//
// Three of them are decisions this command had to make and are argued in the
// package comment; the fourth is an ordinary write. None of them aborts the run.
func importUser(ctx context.Context, o importOptions, rec awsintegration.CognitoUser, t *tally) {
	user, err := migrating.UserFromSource(rec, o.attrs)
	if err != nil {
		if errors.Is(err, migrating.ErrNoEmail) {
			// Reported by the pool's own username, which is the only handle an
			// operator can use to find and fix the record at the source. No
			// address is printed because there is none, which is the point.
			t.noEmail = append(t.noEmail, rec.Username)
			return
		}
		t.failed = append(t.failed, fmt.Sprintf("%s: %v", rec.Username, err))
		return
	}
	user.TenantID = o.flags.tenantID

	if _, err := o.store.CreateMigratedUser(ctx, user, o.ref.Marker()); err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			// Already imported, or registered locally since. SKIPPED, never
			// overwritten, and this is the decision that makes re-running the
			// whole command the recommended recovery: a row that has already
			// adopted a password would otherwise be rewritten with the empty hash
			// and the marker, which would strand the person on a directory they
			// have already left.
			t.existing++
			return
		}
		t.failed = append(t.failed, fmt.Sprintf("%s: %v", rec.Username, err))
		return
	}
	t.written++
}

func reportTally(stdout, stderr *os.File, t tally, resumeToken string) {
	fmt.Fprintf(stdout, "read %d, created %d, already present %d, no email %d, failed %d\n",
		t.read, t.written, t.existing, len(t.noEmail), len(t.failed))

	if len(t.noEmail) > 0 {
		fmt.Fprintf(stderr, "\n%d record(s) had no email address and were skipped. Email is this product's\n"+
			"account identity -- the uniqueness item is keyed on it and every credential flow\n"+
			"addresses it -- so a synthesised one would create a row nobody can log into.\n"+
			"Fix them at the source and re-run; already-imported users are skipped.\n", len(t.noEmail))
		for _, name := range t.noEmail {
			fmt.Fprintf(stderr, "  no email: %s\n", name)
		}
	}
	if len(t.failed) > 0 {
		fmt.Fprintf(stderr, "\n%d record(s) failed to import:\n", len(t.failed))
		for _, line := range t.failed {
			fmt.Fprintf(stderr, "  %s\n", line)
		}
	}
	if resumeToken != "" {
		fmt.Fprintf(stderr, "\nresume with: --start-token %s\n"+
			"(re-running from the beginning is also safe and is the simpler recovery:\n"+
			"every user already imported is skipped rather than overwritten.)\n", resumeToken)
	}
}
