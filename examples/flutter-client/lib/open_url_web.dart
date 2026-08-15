import 'package:web/web.dart' as web;

/// Ramo web: avvia il download dell'APK.
///
/// Stesso meccanismo che la libreria di auth usa per scegliere il trasporto —
/// un conditional import su `dart.library.js_interop` — applicato qui a una
/// cosa molto piu' modesta. Nessuna dipendenza in piu': `package:web` e' gia'
/// nel grafo.
void openUrl(String url) {
  web.window.open(url, '_self');
}
