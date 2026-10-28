/**
 * DeutschThek — Service Worker (PWA Offline Engine)
 * Version: 3.6
 * Architecture: Stale-While-Revalidate with Instant Local Offline Fallback
 */

const CACHE_NAME = 'deutschthek-pwa-v3.6';

// Core shell assets required for 100% offline startup
const PRECACHE_ASSETS = [
  './',
  './index.html',
  './TEST_BANK.html',
  './DOKUMENTATION.html',
  './OFFLINE_WIKI.html',
  './manifest.json',
  './data/official-catalog.js',
  './data/official-catalog.json',
  './js/core/community-swarm.js?v=3.6',
  './js/apps/wiki-app.js',
  './assets/library-bg.webp',
  './assets/wiki-globe.webp',
  './assets/icon-192.png',
  './assets/icon-512.png',
  './assets/icon-maskable-192.png',
  './assets/icon-maskable-512.png',
  './assets/icon.svg',
  './lib/htmldocx/v1/html-docx.js',
  './lib/jszip/v1/jszip.min.js',
  './lib/jszip/jszip.min.js',
  './lib/mammoth/v1/mammoth.browser.js',
  './lib/pdf/v1/pdf.min.js',
  './lib/pdf/v1/pdf.worker.min.js',
  './lib/pdf/v1/pdf-lib.min.js',
  './lib/peerjs/v1/peerjs.min.js'
];

// 1. Installation: Pre-cache all essential offline assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      // Use individual caching to ensure one missing optional asset never aborts install
      const cachePromises = PRECACHE_ASSETS.map(async (url) => {
        try {
          const response = await fetch(url, { cache: 'no-cache' });
          if (response.ok) {
            await cache.put(url, response);
          }
        } catch (err) {
          console.warn('[PWA SW] Pre-cache skipped for:', url, err);
        }
      });
      await Promise.all(cachePromises);
      return self.skipWaiting();
    })
  );
});

// 2. Activation: Clean up stale caches and claim clients immediately
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME && key.startsWith('deutschthek-pwa-')) {
            console.log('[PWA SW] Removing outdated cache:', key);
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// 3. Fetch interceptor: Stale-While-Revalidate with resilient offline fallback
self.addEventListener('fetch', (event) => {
  const request = event.request;

  // Ignore non-GET requests and non-http schemes (e.g. chrome-extension, blob, data)
  if (request.method !== 'GET' || !request.url.startsWith('http')) {
    return;
  }

  const url = new URL(request.url);

  // Bypass WebRTC signaling, STUN/TURN, and external dynamic APIs (Network only)
  if (url.protocol === 'ws:' || url.protocol === 'wss:' || url.hostname.includes('peerjs') || url.hostname.includes('metered.ca')) {
    return;
  }

  // Navigation requests (HTML pages): Network-first with instant Cache fallback
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((networkResp) => {
          if (networkResp && networkResp.status === 200) {
            const clone = networkResp.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          }
          return networkResp;
        })
        .catch(async () => {
          const cachedPage = await caches.match(request);
          if (cachedPage) return cachedPage;
          const fallbackHome = await caches.match('./index.html');
          return fallbackHome || caches.match('./');
        })
    );
    return;
  }

  // Static assets & scripts: Stale-While-Revalidate
  event.respondWith(
    caches.match(request).then((cachedResp) => {
      const fetchPromise = fetch(request)
        .then((networkResp) => {
          if (networkResp && networkResp.status === 200) {
            const clone = networkResp.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
          }
          return networkResp;
        })
        .catch(() => cachedResp);

      // Return cached version immediately if available, otherwise wait for network
      return cachedResp || fetchPromise;
    })
  );
});

// 4. Message handler for user-initiated update skipWaiting
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
