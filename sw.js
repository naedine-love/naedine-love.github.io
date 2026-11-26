const CACHE_NAME = "naedine-pwa-v46";
const APP_SHELL = ["/full-k7x2m9.html", "/icon.svg"];
self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", event => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (request.mode === "navigate") {
    event.respondWith(fetch(new Request(request, { cache: "no-store" })).then(response => {
      if (response && response.ok && /\/full-k7x2m9\.html$/.test(url.pathname)) {
        const copy = response.clone();
        caches.open(CACHE_NAME).then(cache => cache.put("/full-k7x2m9.html", copy));
      }
      return response;
    }).catch(() => caches.match(request, { ignoreSearch: true }).then(cached => cached || caches.match("/full-k7x2m9.html"))));
  }
});
