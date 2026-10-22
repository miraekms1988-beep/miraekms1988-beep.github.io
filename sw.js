/* 서비스워커 - 앱 셸만 캐시한다.
 *
 * 글 데이터(posts/*)는 캐시하지 않는다. 암호문이라 유출 위험은 없지만,
 * 발행 직후 옛 글이 계속 보이는 문제를 피하기 위해 항상 네트워크에서 받는다.
 */
/* 이름을 바꾸면 activate 에서 옛 캐시를 지우고 셸을 새로 받는다.
   deploy-pages.ps1 이 올릴 때 뒤에 앱 셸 지문을 붙인다(v37-1a2b3c4d).
   CSS/JS 가 바뀐 배포마다 이 줄이 바뀌어 휴대폰이 새 셸을 받는다.
   여기 숫자는 손댈 필요 없다. */
const CACHE = 'bond-weekly-v37-67f5487f';
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
    // cache: 'reload' - 브라우저 HTTP 캐시를 건너뛰고 서버에서 새로 받는다.
    // 그냥 addAll 하면 10분짜리 HTTP 캐시에 남은 옛 styles.css 를 새 캐시에
    // 다시 담아 버린다.
    caches.open(CACHE)
      .then((c) => c.addAll(SHELL.map((u) => new Request(u, { cache: 'reload' }))))
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
 * "마지막으로 본 상태를 다시 볼 수 있다" 정도면 충분하다.
 *
 * '네트워크 우선' 만으로는 부족했다. fetch 는 기본값으로 브라우저 HTTP
 * 캐시를 먼저 보는데, GitHub Pages 가 max-age=600 을 주므로 배포 뒤
 * 10분 동안은 네트워크에 가지도 않고 옛 CSS 를 돌려줬다. 휴대폰에서
 * "고쳤다는데 그대로다" 가 그것이었다 (2026-10-19).
 * no-cache 는 매번 서버에 바뀌었는지 묻고(ETag), 안 바뀌었으면 304 로
 * 본문 없이 끝난다. 늘 새 파일을 보면서 데이터는 거의 안 쓴다. */
function fresh(req) {
  // 페이지 이동(navigate) 요청은 옵션을 붙여 다시 만들 수 없다 - 주소로 받는다.
  if (req.mode === 'navigate') return fetch(req.url, { cache: 'no-cache', credentials: 'same-origin' });
  return fetch(req, { cache: 'no-cache' });
}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== location.origin) return;

  e.respondWith(
    fresh(req)
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
