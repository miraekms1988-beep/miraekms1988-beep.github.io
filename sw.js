/* 서비스워커 - 앱 셸만 캐시한다.
 *
 * 글 데이터(posts/*)는 캐시하지 않는다. 암호문이라 유출 위험은 없지만,
 * 발행 직후 옛 글이 계속 보이는 문제를 피하기 위해 항상 네트워크에서 받는다.
 */
/* 이름을 바꾸면 activate 에서 옛 캐시를 지우고 셸을 새로 받는다.
   CSS/JS 를 고쳤는데 화면이 안 바뀌면 여기 숫자를 올린다. */
const CACHE = 'bond-weekly-v11';
const SHELL = [
  './',
  './index.html',
  './app.js',
  './styles.css',
  './manifest.webmanifest',
  './icons/icon.svg',
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

/* 전부 네트워크 우선, 실패하면 캐시.
 *
 * 캐시 우선으로 하면 styles.css/app.js 를 고쳐도 옛 화면이 계속 뜨고,
 * 새 글을 발행해도 목록이 갱신되지 않는다. 오프라인 지원은
 * "마지막으로 본 상태를 다시 볼 수 있다" 정도면 충분하다. */
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== location.origin) return;

  e.respondWith(
    fetch(req)
      .then((res) => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return res;
      })
      .catch(() => caches.match(req).then((cached) => cached || Response.error()))
  );
});
