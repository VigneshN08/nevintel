/* ==========================================================================
   NEVINTEL — service worker

   Only job: receive a Web Push message from the pipeline (pipeline/notify.py,
   sent when the scheduled fetch finds new stories) and show it as a device
   notification, then focus or open the site when it is tapped.

   No caching, no offline mode, no interception of fetch() -- this worker
   does not touch how the site loads. Scope is wherever this file is served
   from (registered with a relative path from the home page), so it covers
   the whole site without any hardcoded path.
   ========================================================================== */

self.addEventListener("push", function (event) {
  var data = {};
  if (event.data) {
    try { data = event.data.json(); } catch (e) {
      data = { title: "NEVINTEL", body: event.data.text() };
    }
  }

  var title = data.title || "NEVINTEL";
  var options = {
    body: data.body || "New security stories are up.",
    // Same generated brand icon used for the manifest / home-screen icon.
    icon: "icon-192.png",
    badge: "icon-192.png",
    data: { url: data.url || "./" },
    tag: "nevintel-digest" // a newer push replaces an unread older one
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  var url = (event.notification.data && event.notification.data.url) || "./";

  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (list) {
      for (var i = 0; i < list.length; i++) {
        var c = list[i];
        if ("focus" in c) return c.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow(url);
    })
  );
});
