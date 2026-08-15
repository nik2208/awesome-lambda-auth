package contract

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TOTP, computed here rather than shelled out to, because the suite is Go and a
// second factor it cannot mint is a second factor it cannot test end to end.
//
// RFC 6238 with the reference's parameters: HMAC-SHA1, 6 digits, 30-second
// step, no truncation options overridden (wire-contract.md §3, totp.strategy.ts
// :5-8 — otplib defaults).
const totpStep = 30 * time.Second

func totpAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	s := strings.ToUpper(strings.TrimSpace(secret))
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("2FA secret %q is not valid base32: %v", secret, err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix())/uint64(totpStep.Seconds()))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

// totpNow returns a code for the current step, having first made sure the step
// will not roll over while the request is in flight. A test that fails because
// it was unlucky with the clock is worse than useless.
func totpNow(t *testing.T, secret string) string {
	t.Helper()
	if left := totpStep - time.Duration(time.Now().UnixNano())%totpStep; left < 3*time.Second {
		time.Sleep(left + 200*time.Millisecond)
	}
	return totpAt(t, secret, time.Now())
}
