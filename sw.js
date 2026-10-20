/* sw.js — service worker de PwnBuilder: cachea el shell para uso sin conexión.
 * Rutas relativas: funciona en cualquier subcarpeta. */
var CACHE = 'pwnbuilder-v2';
var ASSETS = ['./', './index.html', './styles.css', './tools.js', './app.js', './icono.png', './manifest.webmanifest', './icons/icon-192.png', './icons/icon-512.png'];

self.addEventListener('install', function (e) {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(ASSETS); }).catch(function () {}));
});
self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); }));
  }).then(function () { return self.clients.claim(); }));
});
self.addEventListener('fetch', function (e) {
  if (e.request.method !== 'GET') return;
  e.respondWith(caches.match(e.request).then(function (r) {
    return r || fetch(e.request).then(function (resp) {
      var copy = resp.clone();
      caches.open(CACHE).then(function (c) { try { c.put(e.request, copy); } catch (x) {} });
      return resp;
    }).catch(function () { return r; });
  }));
});
