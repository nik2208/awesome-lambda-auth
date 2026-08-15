# Demo Flutter

Consuma **`awesome_node_auth_flutter` da pub.dev, non modificato**, contro uno stack `awesome-lambda-auth` vivo. Si costruisce in due forme, e la coppia è il punto:

| | trasporto | prefisso |
|---|---|---|
| **Web** | cookie di sessione + double-submit CSRF | relativo — `/auth` |
| **Android** | `X-Auth-Strategy: bearer` + `TokenStorage` | assoluto — `https://…/auth` |

La scelta del trasporto **non è di questo codice**: `AuthClient` risolve l'implementazione con un conditional import su `dart.library.js_interop`. Il demo cambia solo il prefisso, e per un motivo preciso — su web serve una sola origin perché i cookie `__Host-` e il token CSRF leggibile dalla pagina lo esigono; su nativo non c'è pagina né origin, e senza browser il CORS non tocca nulla.

L'APK è scaricabile dalla pagina web del demo, così i due rami si provano partendo dallo stesso posto. Il ramo bearer non era mai stato esercitato dal vivo con il client vero.

## Costruire

**Web** — prefisso relativo, serve dietro lo stesso rewrite proxy del demo Angular:

```bash
flutter build web --dart-define=AUTH_API_PREFIX=/auth --dart-define=APK_URL=https://…/app-release.apk
```

**Android** — prefisso assoluto:

```bash
flutter build apk --release --dart-define=AUTH_API_PREFIX=https://<origin>/auth
```

L'APK lo costruisce [`.github/workflows/flutter-demo-apk.yml`](../../.github/workflows/flutter-demo-apk.yml) su tag `flutter-demo-v*` e lo pubblica come release asset. L'origin arriva dalla variabile di repository `DEMO_BASE_URL`: nel repo non finisce mai un dominio reale.

Non è in Amplify perché l'immagine di build predefinita non ha l'SDK Android, e personalizzarla allungherebbe *ogni* build del web per un artefatto che cambia di rado.

## Due difetti del client che questo demo ha fatto emergere

Entrambi sono della stessa famiglia del campo `sub` mancante chiuso da [awesome-go-auth#46](https://github.com/nik2208/awesome-go-auth/pull/46): **un cast non-nullable su un campo che non arriva non degrada un client, lo termina.** Il demo li intercetta e li mostra, invece di morire.

1. **[awesome-node-auth-flutter#21](https://github.com/nik2208/awesome-node-auth-flutter/issues/21)** — `getActiveSessions()` lancia. `SessionInfo.fromJson` legge `json['handle'] as String`, ma il contratto manda `sessionHandle` (`docs/spec/wire-contract.md:236`).

2. **[awesome-node-auth-flutter#22](https://github.com/nik2208/awesome-node-auth-flutter/issues/22)** — `setup2fa()` lancia. `TotpSetupData.fromJson` fa `json['qrCode'] as String`, e questo port non manda `qrCode` (deviazione registrata). Il commento upstream dice «un client disegna da sé `otpauthUrl`», ma questo client non ci arriva: muore prima, e `TotpSetupData` non espone comunque `otpauthUrl`.

Quando saranno chiusi, i `try` in [`home_screen.dart`](lib/screens/home_screen.dart) vanno tolti — restano solo finché servono a rendere visibile il difetto.
