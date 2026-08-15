import 'package:flutter/foundation.dart';

/// Configurazione passata a build time con `--dart-define`.
///
/// Il prefisso e' l'unica cosa che cambia fra le due piattaforme, e cambia per
/// una ragione precisa:
///
/// - **Web**: relativo (`/auth`). La pagina e le route di auth stanno sulla
///   stessa origin perche' Amplify riscrive `/auth/*` verso l'API Gateway.
///   Serve a tenere validi i cookie `__Host-`, a non aver bisogno di CORS e
///   soprattutto a rendere `__Host-csrf-token` leggibile dalla pagina, che e'
///   dove la libreria lo cerca per il double-submit.
///
/// - **Android**: assoluto. Non c'e' nessuna pagina da cui derivare un'origin,
///   e comunque il ramo nativo della libreria non usa i cookie: manda
///   `X-Auth-Strategy: bearer` e tiene i token in `TokenStorage`. Essendo
///   fuori dal browser, l'assenza di CORS non lo tocca.
class DemoConfig {
  /// Prefisso delle route di auth. Su web resta relativo, su nativo va assoluto.
  static const apiPrefix = String.fromEnvironment(
    'AUTH_API_PREFIX',
    defaultValue: '/auth',
  );

  /// Dove scaricare l'APK. La pagina web lo espone cosi' che il ramo bearer si
  /// possa provare partendo dallo stesso posto in cui si prova quello cookie.
  static const apkUrl = String.fromEnvironment('APK_URL');

  /// Il trasporto che la libreria usera'. Non e' una scelta di questo codice:
  /// `AuthClient` risolve l'implementazione con un conditional import su
  /// `dart.library.js_interop`. Qui serve solo a dirlo all'utente.
  static String get transport =>
      kIsWeb ? 'cookie di sessione (web)' : 'bearer token (nativo)';

  static bool get hasApk => apkUrl.isNotEmpty;

  /// Un prefisso relativo su nativo non e' risolvibile: meglio dirlo subito
  /// che lasciare che ogni chiamata fallisca con un errore di URL malformato.
  static String? get misconfiguration {
    if (!kIsWeb && !apiPrefix.startsWith('http')) {
      return 'Su nativo AUTH_API_PREFIX deve essere assoluto (https://…/auth); '
          'ora vale "$apiPrefix".';
    }
    return null;
  }
}
