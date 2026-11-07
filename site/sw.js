const CACHE_NAME = "empiremaps-shell-v5";
const SHELL = ["/", "/manifest.webmanifest", "/icons/empiremaps.svg"];
self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin || url.pathname.startsWith("/api/")) return;
  if (request.mode === "navigate") {
    event.respondWith(fetch(request).then(response => {
      if (response.ok) caches.open(CACHE_NAME).then(cache => cache.put("/", response.clone()));
      return response;
    }).catch(() => caches.match("/")));
    return;
  }
  if (url.pathname.startsWith("/icons/") || url.pathname === "/manifest.webmanifest") {
    event.respondWith(caches.match(request).then(cached => cached || fetch(request)));
  }
});
self.addEventListener("push", event => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (_) { data = { body: event.data ? event.data.text() : "Nowe powiadomienie Empiremaps" }; }
  event.waitUntil(self.registration.showNotification(data.title || "Empiremaps", {
    body: data.body || "Masz nowe powiadomienie.",
    icon: "/icons/empiremaps.svg",
    badge: "/icons/empiremaps.svg",
    tag: data.tag || "empiremaps-alert",
    data: { url: data.url || "/" },
    renotify: true
  }));
});
self.addEventListener("notificationclick", event => {
  event.notification.close();
  const target = new URL((event.notification.data && event.notification.data.url) || "/", self.location.origin).href;
  event.waitUntil(clients.matchAll({ type: "window", includeUncontrolled: true }).then(list => {
    for (const client of list) if ("focus" in client) { client.navigate(target); return client.focus(); }
    return clients.openWindow(target);
  }));
});
