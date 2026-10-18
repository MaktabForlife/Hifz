/* Hifzhelper build 5.2 | js/sw.js */
// V5.2 — shared personal/Maktab Quick Log and edit modes
const CACHE_NAME = 'hifzhelper-v5.2'; // V5.2 release cache
// Kept in sync with index.html's ?v= query strings (V3.6) so this list
// stays correct for whenever this service worker is actually registered
// (Level 2, not yet done) — it is currently inert, this is a
// no-behavior-change consistency edit only.
const ASSETS = [
  './js/maktabAttendanceReport.js?v=5.2',
  './index.html', './manifest.json', './js/pwaManifest.js?v=5.2', 'shared/data.js?v=5.2', 'shared/haidhRules.js?v=5.2', 'shared/journalSchema.js?v=5.2', './js/journalQuickContext.js?v=5.2', './js/journalQuickEditor.js?v=5.2', './appicons/logo.png', './appicons/academy.png', './js/headerDate.js?v=5.2',
  './css/tokens.css?v=5.2', './css/base.css?v=5.2', './css/nav.css?v=5.2', './css/journal-table.css?v=5.2', './css/daily-report.css?v=5.2',
  './css/components.css?v=5.2', './css/detail-pages.css?v=5.2', './css/settings.css?v=5.2', './css/admin.css?v=5.2',
  './css/haidh.css?v=5.2', './css/juzTracker.css?v=5.2', './css/sih.css?v=5.2',
  './js/icons.js?v=5.2', './js/customDate.js?v=5.2', './js/api.js?v=5.2', './js/logContext.js?v=5.2', './js/uiSwitch.js?v=5.2', './js/position.js?v=5.2',
  './js/auth.js?v=5.2', './js/home.js?v=5.2', './js/tajweed.js?v=5.2',
  './js/commentPrivacy.js?v=5.2', './js/maktabSummary.js?v=5.2', './js/maktabDailyReport.js?v=5.2', './js/maktabSettings.js?v=5.2', './js/maktabSetup.js?v=5.2', './js/maktabDay.js?v=5.2', './js/maktabJournal.js?v=5.2', './js/maktabCalendarPage.js?v=5.2', './js/maktabAttendancePage.js?v=5.2', './js/session-timer.js?v=5.2', './js/journal.js?v=5.2', './js/dhorPage.js?v=5.2',
  './js/sabaqPage.js?v=5.2', './js/sabaqDhorPage.js?v=5.2', './js/reflectionCard.js?v=5.2',
  './js/logDetailScreen.js?v=5.2', './js/haidhDetailScreen.js?v=5.2', './js/kaabaTracker.js?v=5.2',
  './js/juzTrackerScreen.js?v=5.2', './js/sihScreen.js?v=5.2', './assets/quran-heart.svg?v=5.2', './assets/quran-heart-regions.json?v=5.2', './assets/quran-heart-lines.svg?v=5.2',
  './js/settingsScreen.js?v=5.2', './js/adminPage.js?v=5.2', './js/app.js?v=5.2'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  event.respondWith(
    caches.match(event.request).then((cached) => {
      const network = fetch(event.request)
        .then((response) => {
          if (response && response.ok) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});
