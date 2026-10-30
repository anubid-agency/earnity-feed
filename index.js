/**
 * earnity-feed — Cloudflare Worker
 * Home feed, search, click/interest tracking.
 * Owns only its own tables: events, user_interests, product_daily_stats,
 * product_dismissals, picker_usage.
 *
 * Bindings: DB (D1), FIREBASE_PROJECT_ID, HASH_SALT, INTERNAL_KEY
 */

const JWKS_URL =
  'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const ALLOWED_HOST = 'earnityug.com';

/* ------------------------- TUNABLE CONSTANTS ------------------------ */
const HALF_LIFE_SECONDS = 14 * 86400;
const INTEREST_CAP = 100_000;

const W_INTEREST = 1.0;
const W_TREND = 0.6;
const W_FRESH = 0.4;
const W_DISCOVERY = 0.3;

const FEED_PAGE_DEFAULT = 20;
const FEED_PAGE_MAX = 20;
const FEED_POOL_SIZE = 200;
const FEED_MAX_OFFSET = 200;
const FEED_BUCKET_SECONDS = 900;
const FEED_MAX_PER_BUSINESS = 3;

const TRENDING_DAYS = 7;
const FRESH_SECONDS = 7 * 86400;
const POPULAR_WINDOW_DAYS = 7;

const SEARCH_PAGE_SIZE = 20;
const SUGGEST_LIMIT = 8;

const EVENT_WEIGHTS = {
  view: 1,
  click: 3,
  three_dot_open: 2,
  search: 2,
  filter: 3,
  share: 5,
  not_interested: -8,
  buy: 10,
  slot_claim: 6,
};

const CLIENT_EVENT_TYPES = new Set([
  'view', 'click', 'three_dot_open', 'search', 'filter', 'share', 'not_interested',
]);
const INTERNAL_EVENT_TYPES = new Set(['buy', 'slot_claim']);

const MAX_EVENTS_PER_BATCH = 20;
const MAX_QUERY_LEN = 80;
const MAX_SEARCH_Q_LEN = 60;
const MAX_SUGGEST_Q_LEN = 40;

const RATE_OWNER_PER_HOUR = 200;
const RATE_IP_PER_HOUR = 1000;

const PURGE_EVENTS_DAYS = 90;
const PURGE_STATS_DAYS = 30;
const PURGE_VISITOR_INTERESTS_DAYS = 90;
const PURGE_CHUNK = 5000;

const MAX_BODY_BYTES = 8192;
const MAX_ID_LENGTH = 128;
const CLOCK_SKEW_SECONDS = 60;
const JWKS_CACHE_SECONDS = 3600;
const KEY_CACHE_MS = 3600_000;
const MAX_SUB_LENGTH = 128;
const VISITOR_ID_RE = /^[A-Za-z0-9_-]{22,36}$/;

const enc = new TextEncoder();

let jwksMem = { keys: null, expires: 0 };
const keyMem = new Map();
let hmacKeyCache = { salt: null, key: null };

class HttpError extends Error {
  constructor(status, code, extra) {
    super(code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

function json(data, status, cors, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...cors,
      ...extraHeaders,
    },
  });
}

function publicJson(data, status, cors, seconds) {
  return json(data, status, cors, {
    'Cache-Control': `public, max-age=${seconds || 30}`,
  });
}

function corsHeaders(origin) {
  if (!origin) return { Vary: 'Origin' };
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Visitor-Id',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

function isAllowedOrigin(origin) {
  if (!origin) return true;
  try {
    const u = new URL(origin);
    return (
      u.protocol === 'https:' &&
      (u.hostname === ALLOWED_HOST || u.hostname.endsWith('.' + ALLOWED_HOST))
    );
  } catch {
    return false;
  }
}

function assertEnv(env, names) {
  for (const name of names) {
    if (!env[name]) {
      console.error('missing_env', { name });
      throw new HttpError(500, 'server_misconfigured');
    }
  }
}

function generateId(prefix) {
  const rand = crypto.getRandomValues(new Uint8Array(8));
  return (
    prefix +
    Date.now().toString(36) +
    Array.from(rand)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  );
}

function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function b64urlDecode(input) {
  let s = input.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function b64urlEncodeUtf8(str) {
  const bytes = enc.encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64urlDecodeUtf8(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function timingSafeEqual(a, b) {
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

async function readJson(request) {
  const ct = (request.headers.get('content-type') || '').toLowerCase();
  if (ct !== 'application/json' && !ct.startsWith('application/json;')) {
    throw new HttpError(415, 'unsupported_media_type');
  }
  const len = Number(request.headers.get('content-length') || '0');
  if (Number.isFinite(len) && len > MAX_BODY_BYTES) {
    throw new HttpError(413, 'payload_too_large');
  }
  const text = await request.text();
  if (enc.encode(text).length > MAX_BODY_BYTES) {
    throw new HttpError(413, 'payload_too_large');
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new HttpError(400, 'invalid_json');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new HttpError(400, 'invalid_json');
  }
  return data;
}

async function hmacHex(env, message) {
  let key = hmacKeyCache.key;
  if (!key || hmacKeyCache.salt !== env.HASH_SALT) {
    key = await crypto.subtle.importKey(
      'raw',
      enc.encode(env.HASH_SALT),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    hmacKeyCache = { salt: env.HASH_SALT, key };
  }
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return bufToHex(sig);
}

/* ------------------------------------------------------------------ */
/* Firebase ID token verification (same as earnity-catalog)           */
/* ------------------------------------------------------------------ */

async function getJwks(env, force) {
  const now = Date.now();
  if (!force && jwksMem.keys && jwksMem.expires > now) return jwksMem.keys;
  const res = await fetch(
    JWKS_URL,
    force
      ? { cache: 'no-store', cf: { cacheTtl: 0, cacheEverything: false } }
      : { cf: { cacheTtl: JWKS_CACHE_SECONDS, cacheEverything: true } }
  );
  if (!res.ok) throw new Error('jwks_fetch_failed');
  const data = await res.json();
  if (!Array.isArray(data.keys)) throw new Error('jwks_invalid');
  jwksMem = { keys: data.keys, expires: now + JWKS_CACHE_SECONDS * 1000 };
  return data.keys;
}

async function importJwk(jwk) {
  const cached = keyMem.get(jwk.kid);
  if (cached && cached.expires > Date.now()) return cached.key;
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
  keyMem.set(jwk.kid, { key, expires: Date.now() + KEY_CACHE_MS });
  return key;
}

async function getKey(kid, env) {
  let keys = await getJwks(env, false);
  let jwk = keys.find((k) => k.kid === kid);
  if (!jwk) {
    keys = await getJwks(env, true);
    jwk = keys.find((k) => k.kid === kid);
  }
  if (!jwk) throw new Error('key_not_found');
  return importJwk(jwk);
}

async function verifyFirebaseToken(token, env, now) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('malformed');
  const [headerPart, payloadPart, sigPart] = parts;
  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(headerPart)));
  if (header.alg !== 'RS256' || typeof header.kid !== 'string') {
    throw new Error('alg');
  }
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadPart)));
  const key = await getKey(header.kid, env);
  const data = enc.encode(`${headerPart}.${payloadPart}`);
  const sig = b64urlDecode(sigPart);
  const valid = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    sig,
    data
  );
  if (!valid) throw new Error('signature');
  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp) || payload.exp <= now) {
    throw new Error('exp');
  }
  if (
    typeof payload.iat !== 'number' ||
    !Number.isFinite(payload.iat) ||
    payload.iat > now + CLOCK_SKEW_SECONDS
  ) {
    throw new Error('iat');
  }
  if (
    typeof payload.auth_time !== 'number' ||
    !Number.isFinite(payload.auth_time) ||
    payload.auth_time > now + CLOCK_SKEW_SECONDS
  ) {
    throw new Error('auth_time');
  }
  if (payload.aud !== env.FIREBASE_PROJECT_ID) throw new Error('aud');
  if (payload.iss !== `https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}`) {
    throw new Error('iss');
  }
  if (
    typeof payload.sub !== 'string' ||
    !payload.sub ||
    payload.sub.length > MAX_SUB_LENGTH
  ) {
    throw new Error('sub');
  }
  return payload;
}

async function loadUserFromRequest(request, env, now) {
  const auth = request.headers.get('Authorization');
  if (!auth) return null;
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) throw new HttpError(401, 'unauthorized');
  let payload;
  try {
    payload = await verifyFirebaseToken(match[1], env, now);
  } catch {
    throw new HttpError(401, 'invalid_token');
  }
  const user = await env.DB.prepare(
    'SELECT id, account_type, status FROM users WHERE firebase_uid = ? LIMIT 1'
  ).bind(payload.sub).first();
  if (!user) throw new HttpError(404, 'not_registered');
  if (user.status === 'blocked') throw new HttpError(403, 'account_blocked');
  return user;
}

/* ------------------------------------------------------------------ */
/* Identity / privacy                                                 */
/* ------------------------------------------------------------------ */

function validateVisitorId(raw) {
  if (raw == null) return null;
  if (typeof raw !== 'string') throw new HttpError(400, 'invalid_visitor_id');
  const v = raw.trim();
  if (!VISITOR_ID_RE.test(v)) throw new HttpError(400, 'invalid_visitor_id');
  return v;
}

function hasPrivacyHeader(request) {
  const dnt = request.headers.get('DNT');
  const gpc = request.headers.get('Sec-GPC');
  return dnt === '1' || gpc === '1';
}

function resolveOwner(request, user) {
  if (user) return { ownerKey: 'u:' + user.id, userId: user.id, visitorId: null };
  const headerRaw = request.headers.get('X-Visitor-Id');
  const visitorId = validateVisitorId(headerRaw);
  if (!visitorId) return null;
  return { ownerKey: 'v:' + visitorId, userId: null, visitorId };
}

function getRegion(cf) {
  const country = cf && typeof cf.country === 'string' ? cf.country : null;
  if (!country) return 'ALL';
  const region = cf && typeof cf.region === 'string' && cf.region ? cf.region : 'unknown';
    return (country + ':' + region).slice(0, 32);
}

async function hashClientIp(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || '';
  if (!ip) return null;
  return hmacHex(env, 'ip:' + ip);
}

/* ------------------------------------------------------------------ */
/* Interest math                                                      */
/* ------------------------------------------------------------------ */

function decayScore(oldScore, elapsedSeconds) {
  if (oldScore <= 0) return 0;
  if (elapsedSeconds <= 0) return oldScore;
  const factor = Math.pow(0.5, elapsedSeconds / HALF_LIFE_SECONDS);
  return Math.floor(oldScore * factor);
}

/* ------------------------------------------------------------------ */
/* Effective price + slots                                            */
/* ------------------------------------------------------------------ */

function effectivePrice(product, now) {
  const hasOffer =
    product.offer_price_ugx != null &&
    product.offer_starts_at != null &&
    product.offer_ends_at != null &&
    now >= Number(product.offer_starts_at) &&
    now < Number(product.offer_ends_at);
  const price = hasOffer ? Number(product.offer_price_ugx) : Number(product.price_ugx);
  return { price, offer_active: hasOffer };
}

function firstImage(product) {
  try {
    const arr = JSON.parse(product.image_ids || '[]');
    return Array.isArray(arr) && arr.length > 0 ? String(arr[0]) : null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* /health                                                            */
/* ------------------------------------------------------------------ */

async function handleHealth(env, now, cors) {
  return json({ ok: true, service: 'earnity-feed', time: now }, 200, cors);
}

/* ------------------------------------------------------------------ */
/* /chips                                                             */
/* ------------------------------------------------------------------ */

async function handleChips(env, cors) {
  assertEnv(env, ['DB']);
  const rows = await env.DB.prepare(
    'SELECT id, name, sort_order FROM categories ORDER BY sort_order ASC, name ASC'
  ).all();
  const chips = [
    { id: 'all', name: 'All', kind: 'filter' },
    { id: 'popular', name: 'Popular', kind: 'filter' },
    ...(rows.results || []).map((r) => ({ id: r.id, name: r.name, kind: 'category' })),
  ];
  return publicJson({ chips }, 200, cors, 60);
}

/* ------------------------------------------------------------------ */
/* Ranking helpers                                                    */
/* ------------------------------------------------------------------ */

function normaliseMap(map) {
  let max = 0;
  for (const v of map.values()) if (v > max) max = v;
  const out = new Map();
  if (max <= 0) return out;
  for (const [k, v] of map) out.set(k, v / max);
  return out;
}

async function loadTrendingPoints(env, region, now) {
  const today = Math.floor(now / 86400);
  const fromDay = today - (TRENDING_DAYS - 1);
  const rows = await env.DB.prepare(
    `SELECT product_id, SUM(points) AS pts
     FROM product_daily_stats
     WHERE day >= ? AND region IN (?, 'ALL')
     GROUP BY product_id`
  ).bind(fromDay, region).all();
  const map = new Map();
  for (const r of rows.results || []) map.set(r.product_id, Number(r.pts || 0));
  return map;
}

async function loadOwnerInterests(env, ownerKey) {
  const rows = await env.DB.prepare(
    'SELECT category_id, score FROM user_interests WHERE owner_key = ?'
  ).bind(ownerKey).all();
  const map = new Map();
  for (const r of rows.results || []) map.set(r.category_id, Number(r.score));
  return map;
}

async function loadDismissedProductIds(env, ownerKey) {
  if (!ownerKey) return new Set();
  const rows = await env.DB.prepare(
    'SELECT product_id FROM product_dismissals WHERE owner_key = ?'
  ).bind(ownerKey).all();
  return new Set((rows.results || []).map((r) => r.product_id));
}

/* ------------------------------------------------------------------ */
/* /feed                                                              */
/* ------------------------------------------------------------------ */

async function handleFeed(request, env, now, cors) {
  assertEnv(env, ['DB', 'FIREBASE_PROJECT_ID']);

  const url = new URL(request.url);
  const limitRaw = url.searchParams.get('limit');
  let limit = FEED_PAGE_DEFAULT;
  if (limitRaw != null) {
    const n = Number(limitRaw);
    if (!Number.isInteger(n) || n < 1 || n > FEED_PAGE_MAX) {
      throw new HttpError(400, 'invalid_limit');
    }
    limit = n;
  }

  const categoryParam = url.searchParams.get('category');
  let categoryId = null;
  if (categoryParam && categoryParam !== 'all') {
    if (categoryParam === 'popular') {
      categoryId = null;
    } else {
      if (typeof categoryParam !== 'string' || categoryParam.length > 64) {
        throw new HttpError(400, 'invalid_category');
      }
      const c = await env.DB.prepare('SELECT id FROM categories WHERE id = ? LIMIT 1')
        .bind(categoryParam).first();
      if (!c) throw new HttpError(400, 'invalid_category');
      categoryId = categoryParam;
    }
  }

  const user = await loadUserFromRequest(request, env, now);
  const privacy = hasPrivacyHeader(request);
  const owner = resolveOwner(request, user);
  const region = getRegion(request.cf);

  const bucket = Math.floor(now / FEED_BUCKET_SECONDS);
  let offset = 0;
  const cursorRaw = url.searchParams.get('cursor');
  if (cursorRaw) {
    try {
      const decoded = JSON.parse(b64urlDecodeUtf8(cursorRaw));
      if (!decoded || typeof decoded.offset !== 'number' || !Number.isFinite(decoded.offset)) {
        throw new Error('bad');
      }
      offset = Math.max(0, Math.min(FEED_MAX_OFFSET, Math.floor(decoded.offset)));
    } catch {
      throw new HttpError(400, 'invalid_cursor');
    }
  }

  let interests = new Map();
  let dismissed = new Set();
  if (!privacy && owner) {
    interests = await loadOwnerInterests(env, owner.ownerKey);
    dismissed = await loadDismissedProductIds(env, owner.ownerKey);
  }

  const trending = await loadTrendingPoints(env, region, now);
  const normalisedTrend = normaliseMap(trending);
  const normalisedInterest = normaliseMap(interests);

  const poolMap = new Map();

  async function fetchProducts(sql, binds) {
    const rows = await env.DB.prepare(sql).bind(...binds).all();
    for (const r of rows.results || []) poolMap.set(r.id, r);
  }

  const baseWhere = `
    FROM products p
    JOIN businesses b ON b.id = p.business_id
    WHERE p.status = 'active' AND b.approval_status = 'approved'
    ${categoryId ? 'AND p.category_id = ?' : ''}
  `;
  const baseBinds = categoryId ? [categoryId] : [];

  const topInterestCats = [...interests.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([c]) => c);
  if (!privacy && !categoryId && topInterestCats.length > 0) {
    const placeholders = topInterestCats.map(() => '?').join(',');
    await fetchProducts(
      `SELECT p.*, b.discovery_until ${baseWhere} AND p.category_id IN (${placeholders})
       ORDER BY p.created_at DESC LIMIT 60`,
      [...baseBinds, ...topInterestCats]
    );
  }

  const trendIds = [...trending.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 80)
    .map(([id]) => id);
  if (trendIds.length > 0) {
    const placeholders = trendIds.map(() => '?').join(',');
    await fetchProducts(
      `SELECT p.*, b.discovery_until ${baseWhere} AND p.id IN (${placeholders}) LIMIT 80`,
      [...baseBinds, ...trendIds]
    );
  }

  await fetchProducts(
    `SELECT p.*, b.discovery_until ${baseWhere} ORDER BY p.created_at DESC LIMIT 100`,
    baseBinds
  );

  const candidates = [...poolMap.values()]
    .filter((p) => !dismissed.has(p.id))
    .slice(0, FEED_POOL_SIZE);

   
  const scored = candidates.map((p) => {
    const { price, offer_active } = effectivePrice(p, now);
    const trendPts = trending.get(p.id) || 0;
    const trendNorm = normalisedTrend.get(p.id) || 0;
    const interestNorm = normalisedInterest.get(p.category_id) || 0;
    const age = now - Number(p.created_at);
    const fresh = age >= 0 && age < FRESH_SECONDS ? 1 : 0;
    const discovery = p.discovery_until && Number(p.discovery_until) > now ? 1 : 0;

    const coldStart = privacy || !owner || interests.size === 0;

    let score;
    if (coldStart) {
      score = trendNorm * 1.0 + fresh * 0.1 + (Number(p.created_at) / 1e12);
    } else {
      score =
        interestNorm * W_INTEREST +
        trendNorm * W_TREND +
        fresh * W_FRESH +
        discovery * W_DISCOVERY;
    }

    return {
      product: p,
      price,
      offer_active,
      trendPts,
      score,
           slotsUsed: 0,
    };
  });

  function stableHash(id, b) {
    let h = 2166136261 >>> 0;
    const s = id + ':' + b;
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = (h * 16777619) >>> 0;
    }
    return h / 4294967295;
  }

  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    const ha = stableHash(a.product.id, bucket);
    const hb = stableHash(b.product.id, bucket);
    if (hb !== ha) return hb - ha;
    return a.product.id < b.product.id ? -1 : 1;
  });

  // Build the diversified order once, then slice by offset so pages never overlap.
  const ordered = [];
  let remaining = scored.slice();
  while (remaining.length > 0 && ordered.length < FEED_POOL_SIZE) {
    const perBiz = new Map();
    const block = [];
    const rest = [];
    for (const s of remaining) {
      const biz = s.product.business_id;
      const used = perBiz.get(biz) || 0;
      if (block.length < FEED_PAGE_MAX && used < FEED_MAX_PER_BUSINESS) {
        block.push(s);
        perBiz.set(biz, used + 1);
      } else {
        rest.push(s);
      }
    }
    ordered.push(...block);
    remaining = rest;
  }
    const pageItems = ordered.slice(offset, offset + limit);

  const slotsUsedMap = new Map();
  if (pageItems.length > 0) {
    const ids = pageItems.map((s) => s.product.id);
    const ph = ids.map(() => '?').join(',');
    const rows = await env.DB.prepare(
      `SELECT product_id, COUNT(*) AS n FROM product_referee_slots
       WHERE status IN ('pending','active') AND product_id IN (${ph})
       GROUP BY product_id`
    ).bind(...ids).all();
    for (const r of rows.results || []) slotsUsedMap.set(r.product_id, Number(r.n));
  }
  for (const s of pageItems) s.slotsUsed = slotsUsedMap.get(s.product.id) || 0;

  const nextOffset = offset + pageItems.length;
  const hasMore = nextOffset < ordered.length && nextOffset < FEED_MAX_OFFSET;
  const next_cursor = hasMore
    ? b64urlEncodeUtf8(JSON.stringify({ bucket, offset: nextOffset }))
    : null;

  const bizIds = [...new Set(pageItems.map((s) => s.product.business_id))];
  const bizMap = new Map();
  if (bizIds.length > 0) {
    const placeholders = bizIds.map(() => '?').join(',');
    const rows = await env.DB.prepare(
      `SELECT id, name, subdomain, level FROM businesses WHERE id IN (${placeholders})`
    ).bind(...bizIds).all();
    for (const r of rows.results || []) bizMap.set(r.id, r);
  }

  const items = pageItems.map((s) => {
    const p = s.product;
    const biz = bizMap.get(p.business_id);
    const commissionUgx = Math.floor((s.price * Number(p.commission_bps)) / 10000);
    return {
      id: p.id,
      name: p.name,
      effective_price_ugx: s.price,
      price_ugx: Number(p.price_ugx),
      offer_active: s.offer_active,
      image: firstImage(p),
      category_id: p.category_id,
      commission_bps: Number(p.commission_bps),
      commission_ugx: commissionUgx,
      slots_free: Math.max(0, Number(p.referee_max) - s.slotsUsed),
      delivery_days: Number(p.delivery_days),
      business: biz
        ? { id: biz.id, name: biz.name, subdomain: biz.subdomain, level: Number(biz.level) }
        : null,
    };
  });

  return json({ items, next_cursor }, 200, cors);
}

/* ------------------------------------------------------------------ */
/* /search                                                            */
/* ------------------------------------------------------------------ */

function escapeLike(s) {
  return s.replace(/[\\%_]/g, (m) => '\\' + m);
}

async function handleSearch(request, env, now, cors) {
  assertEnv(env, ['DB', 'FIREBASE_PROJECT_ID']);
  const url = new URL(request.url);

  const qRaw = url.searchParams.get('q') ?? '';
  const q = String(qRaw).trim();
  if (q.length < 2 || q.length > MAX_SEARCH_Q_LEN) {
    throw new HttpError(400, 'invalid_query');
  }

  const catRaw = url.searchParams.get('category');
  let categoryId = null;
  if (catRaw && catRaw !== 'all' && catRaw !== 'popular') {
    if (catRaw.length > 64) throw new HttpError(400, 'invalid_category');
    const c = await env.DB.prepare('SELECT id FROM categories WHERE id = ? LIMIT 1')
      .bind(catRaw).first();
    if (!c) throw new HttpError(400, 'invalid_category');
    categoryId = catRaw;
  }

  let offset = 0;
  const cursorRaw = url.searchParams.get('cursor');
  if (cursorRaw) {
    try {
      const decoded = JSON.parse(b64urlDecodeUtf8(cursorRaw));
      if (!decoded || typeof decoded.offset !== 'number' || !Number.isFinite(decoded.offset)) {
        throw new Error('bad');
      }
      offset = Math.max(0, Math.min(500, Math.floor(decoded.offset)));
    } catch {
      throw new HttpError(400, 'invalid_cursor');
    }
  }

  const like = '%' + escapeLike(q) + '%';
  const prefix = escapeLike(q) + '%';
  const exact = q;

  const catClause = categoryId ? 'AND p.category_id = ?' : '';
  const catBind = categoryId ? [categoryId] : [];

  const productsRows = await env.DB.prepare(
    `SELECT p.*, b.name AS biz_name, b.subdomain AS biz_subdomain, b.level AS biz_level,
       CASE
         WHEN p.name = ? COLLATE NOCASE THEN 0
         WHEN p.name LIKE ? ESCAPE '\\' COLLATE NOCASE THEN 1
         WHEN p.name LIKE ? ESCAPE '\\' COLLATE NOCASE THEN 2
         WHEN b.name LIKE ? ESCAPE '\\' COLLATE NOCASE THEN 3
         WHEN b.subdomain LIKE ? ESCAPE '\\' COLLATE NOCASE THEN 3
         WHEN p.description LIKE ? ESCAPE '\\' COLLATE NOCASE THEN 4
         ELSE 9
       END AS rank_bucket
     FROM products p
     JOIN businesses b ON b.id = p.business_id
     WHERE p.status = 'active' AND b.approval_status = 'approved' ${catClause}
       AND (
         p.name LIKE ? ESCAPE '\\' COLLATE NOCASE
         OR p.description LIKE ? ESCAPE '\\' COLLATE NOCASE
         OR b.name LIKE ? ESCAPE '\\' COLLATE NOCASE
         OR b.subdomain LIKE ? ESCAPE '\\' COLLATE NOCASE
       )
     ORDER BY rank_bucket ASC, p.created_at DESC
     LIMIT ? OFFSET ?`
  ).bind(
    exact, prefix, like, like, like, like,
    ...catBind,
    like, like, like, like,
    SEARCH_PAGE_SIZE + 1, offset
  ).all();

  const prodResults = productsRows.results || [];
  const hasMoreProducts = prodResults.length > SEARCH_PAGE_SIZE;
  const pageProducts = prodResults.slice(0, SEARCH_PAGE_SIZE);

  let stores = [];
  if (offset === 0) {
    const storeRows = await env.DB.prepare(
      `SELECT id, name, subdomain, logo_public_id, level, delivered_sales,
              CASE
                WHEN name = ? COLLATE NOCASE THEN 0
                WHEN name LIKE ? ESCAPE '\\' COLLATE NOCASE THEN 1
                WHEN subdomain LIKE ? ESCAPE '\\' COLLATE NOCASE THEN 2
                ELSE 3
              END AS rank_bucket
       FROM businesses
       WHERE approval_status = 'approved'
         AND (name LIKE ? ESCAPE '\\' COLLATE NOCASE
              OR subdomain LIKE ? ESCAPE '\\' COLLATE NOCASE)
       ORDER BY rank_bucket ASC, level DESC, delivered_sales DESC
       LIMIT 10`
    ).bind(exact, prefix, prefix, like, like).all();
    stores = (storeRows.results || []).map((r) => ({
      id: r.id,
      name: r.name,
      subdomain: r.subdomain,
      logo_public_id: r.logo_public_id,
      level: Number(r.level),
      delivered_sales: Number(r.delivered_sales),
    }));
  }

  const slotsUsed = new Map();
  if (pageProducts.length > 0) {
    const ids = pageProducts.map((p) => p.id);
    const placeholders = ids.map(() => '?').join(',');
    const rows = await env.DB.prepare(
      `SELECT product_id, COUNT(*) AS n FROM product_referee_slots
       WHERE status IN ('pending','active') AND product_id IN (${placeholders})
       GROUP BY product_id`
    ).bind(...ids).all();
    for (const r of rows.results || []) slotsUsed.set(r.product_id, Number(r.n));
  }

  const products = pageProducts.map((p) => {
    const { price, offer_active } = effectivePrice(p, now);
    const commissionUgx = Math.floor((price * Number(p.commission_bps)) / 10000);
    return {
      id: p.id,
      name: p.name,
      effective_price_ugx: price,
      price_ugx: Number(p.price_ugx),
      offer_active,
      image: firstImage(p),
      category_id: p.category_id,
      commission_bps: Number(p.commission_bps),
      commission_ugx: commissionUgx,
      slots_free: Math.max(0, Number(p.referee_max) - (slotsUsed.get(p.id) || 0)),
      delivery_days: Number(p.delivery_days),
      business: {
        id: p.business_id,
        name: p.biz_name,
        subdomain: p.biz_subdomain,
        level: Number(p.biz_level),
      },
    };
  });

  const next_cursor =
    hasMoreProducts && offset + pageProducts.length < 500
      ? b64urlEncodeUtf8(JSON.stringify({ offset: offset + pageProducts.length }))
      : null;

  const origin = request.headers.get('Origin');
  const anonymousClean =
    !request.headers.get('Authorization') &&
    !request.headers.get('X-Visitor-Id') &&
    !hasPrivacyHeader(request);

  const payload = { products, stores, next_cursor };
  if (anonymousClean) {
    return publicJson(payload, 200, corsHeaders(origin), 30);
  }
  return json(payload, 200, corsHeaders(origin));
}

/* ------------------------------------------------------------------ */
/* /search/suggest                                                    */
/* ------------------------------------------------------------------ */

async function handleSuggest(request, env, now, cors) {
  assertEnv(env, ['DB']);
  const url = new URL(request.url);
  const q = String(url.searchParams.get('q') || '').trim();
  if (q.length < 2 || q.length > MAX_SUGGEST_Q_LEN) {
    throw new HttpError(400, 'invalid_query');
  }
  const prefix = escapeLike(q) + '%';
  const like = '%' + escapeLike(q) + '%';

  const productRows = await env.DB.prepare(
    `SELECT p.name FROM products p
     JOIN businesses b ON b.id = p.business_id
     WHERE p.status = 'active' AND b.approval_status = 'approved'
       AND p.name LIKE ? ESCAPE '\\' COLLATE NOCASE
     ORDER BY (p.name LIKE ? ESCAPE '\\' COLLATE NOCASE) DESC, p.created_at DESC
     LIMIT ?`
  ).bind(like, prefix, SUGGEST_LIMIT).all();

  const storeRows = await env.DB.prepare(
    `SELECT name FROM businesses
     WHERE approval_status = 'approved'
       AND name LIKE ? ESCAPE '\\' COLLATE NOCASE
     ORDER BY (name LIKE ? ESCAPE '\\' COLLATE NOCASE) DESC, level DESC
     LIMIT ?`
  ).bind(like, prefix, SUGGEST_LIMIT).all();

  const seen = new Set();
  const out = [];
  for (const r of productRows.results || []) {
    const key = 'p:' + r.name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ type: 'product', text: r.name });
    if (out.length >= SUGGEST_LIMIT) break;
  }
  for (const r of storeRows.results || []) {
    if (out.length >= SUGGEST_LIMIT) break;
    const key = 's:' + r.name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ type: 'store', text: r.name });
  }

  return publicJson({ suggestions: out }, 200, cors, 30);
}

/* ------------------------------------------------------------------ */
/* POST /events                                                       */
/* ------------------------------------------------------------------ */

function validateClientEvent(raw, idx) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HttpError(400, 'invalid_event');
  }
  const type = raw.type;
  if (typeof type !== 'string' || !CLIENT_EVENT_TYPES.has(type)) {
    throw new HttpError(400, 'invalid_event_type');
  }
  const out = { type };
  if (raw.product_id != null) {
    if (typeof raw.product_id !== 'string' || raw.product_id.length === 0 || raw.product_id.length >= MAX_ID_LENGTH) {
      throw new HttpError(400, 'invalid_product_id');
    }
    out.product_id = raw.product_id;
  }
  if (raw.business_id != null) {
    if (typeof raw.business_id !== 'string' || raw.business_id.length === 0 || raw.business_id.length >= MAX_ID_LENGTH) {
      throw new HttpError(400, 'invalid_business_id');
    }
    out.business_id = raw.business_id;
  }
  if (raw.category_id != null) {
    if (typeof raw.category_id !== 'string' || raw.category_id.length === 0 || raw.category_id.length > 64) {
      throw new HttpError(400, 'invalid_category_id');
    }
    out.category_id = raw.category_id;
  }
  if (raw.query != null) {
    if (typeof raw.query !== 'string' || raw.query.length > MAX_QUERY_LEN) {
      throw new HttpError(400, 'invalid_query');
    }
    out.query = raw.query;
  }
  return out;
}

async function handlePostEvents(request, env, now, cors) {
  assertEnv(env, ['DB', 'HASH_SALT', 'FIREBASE_PROJECT_ID']);

  const user = await loadUserFromRequest(request, env, now);
  const privacy = hasPrivacyHeader(request);
  if (privacy) {
    try { await readJson(request); } catch { /* ignore */ }
    return json({ stored: false, reason: 'privacy_header' }, 200, cors);
  }

  const owner = resolveOwner(request, user);
  if (!owner) {
    throw new HttpError(400, 'visitor_id_required');
  }

  const body = await readJson(request);
  if (!Array.isArray(body.events) || body.events.length === 0) {
    throw new HttpError(400, 'invalid_events');
  }
  if (body.events.length > MAX_EVENTS_PER_BATCH) {
    throw new HttpError(400, 'too_many_events');
  }

  const events = body.events.map((raw, i) => validateClientEvent(raw, i));

  const productIds = [...new Set(events.map((e) => e.product_id).filter(Boolean))];
  const productMap = new Map();
  if (productIds.length > 0) {
    const placeholders = productIds.map(() => '?').join(',');
    const rows = await env.DB.prepare(
      `SELECT p.id, p.business_id, p.category_id
       FROM products p JOIN businesses b ON b.id = p.business_id
       WHERE p.id IN (${placeholders})
         AND p.status = 'active' AND b.approval_status = 'approved'`
    ).bind(...productIds).all();
    for (const r of rows.results || []) productMap.set(r.id, r);
  }

  const enriched = events.map((e) => {
    const out = { ...e };
    if (e.product_id) {
      const p = productMap.get(e.product_id);
      if (!p) throw new HttpError(400, 'invalid_product_id');
      out.business_id = p.business_id;
      out.category_id = p.category_id;
    }
    return out;
  });

  const validCats = new Set(
    ((await env.DB.prepare('SELECT id FROM categories').all()).results || []).map((r) => r.id)
  );
  for (const e of enriched) {
    if (e.category_id && !validCats.has(e.category_id)) {
      throw new HttpError(400, 'invalid_category_id');
    }
  }

  const ipHash = await hashClientIp(request, env);
  const region = getRegion(request.cf);
  const hourAgo = now - 3600;

  const ownerCount = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM events WHERE owner_key = ? AND created_at > ?'
  ).bind(owner.ownerKey, hourAgo).first();
  if (Number(ownerCount?.n || 0) + enriched.length > RATE_OWNER_PER_HOUR) {
    throw new HttpError(429, 'rate_limited');
  }
  if (ipHash) {
    const ipCount = await env.DB.prepare(
      'SELECT COUNT(*) AS n FROM events WHERE ip_hash = ? AND created_at > ?'
    ).bind(ipHash, hourAgo).first();
    if (Number(ipCount?.n || 0) + enriched.length > RATE_IP_PER_HOUR) {
      throw new HttpError(429, 'rate_limited');
    }
  }

  const involvedCats = [...new Set(enriched.map((e) => e.category_id).filter(Boolean))];
  const currentInterests = new Map();
  if (involvedCats.length > 0) {
    const placeholders = involvedCats.map(() => '?').join(',');
    const rows = await env.DB.prepare(
      `SELECT category_id, score, updated_at FROM user_interests
       WHERE owner_key = ? AND category_id IN (${placeholders})`
    ).bind(owner.ownerKey, ...involvedCats).all();
    for (const r of rows.results || []) {
      currentInterests.set(r.category_id, { score: Number(r.score), updated_at: Number(r.updated_at) });
    }
  }

  const interestDeltas = new Map();
  for (const e of enriched) {
    const w = EVENT_WEIGHTS[e.type] || 0;
    if (!w) continue;
    if ((e.type === 'search' || e.type === 'filter') && !e.category_id) continue;
    if (!e.category_id) continue;
    interestDeltas.set(e.category_id, (interestDeltas.get(e.category_id) || 0) + w);
  }

  const batchStmts = [];

  for (const e of enriched) {
    batchStmts.push(
      env.DB.prepare(
        `INSERT INTO events
           (id, owner_key, user_id, visitor_id, type, product_id, business_id,
            category_id, query, region, ip_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        generateId('evt_'),
        owner.ownerKey,
        owner.userId,
        owner.visitorId,
        e.type,
        e.product_id || null,
        e.business_id || null,
        e.category_id || null,
        e.query || null,
        region,
        ipHash,
        now
      )
    );
  }

  for (const [categoryId, delta] of interestDeltas) {
    const cur = currentInterests.get(categoryId) || { score: 0, updated_at: now };
    const decayed = decayScore(cur.score, Math.max(0, now - cur.updated_at));
    let next = decayed + delta;
    if (next < 0) next = 0;
    if (next > INTEREST_CAP) next = INTEREST_CAP;

    batchStmts.push(
      env.DB.prepare(
        `INSERT INTO user_interests (owner_key, category_id, score, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(owner_key, category_id) DO UPDATE SET
           score = excluded.score,
           updated_at = excluded.updated_at`
      ).bind(owner.ownerKey, categoryId, next, now)
    );
  }

  const today = Math.floor(now / 86400);
  for (const e of enriched) {
    if (!e.product_id) continue;
    const w = EVENT_WEIGHTS[e.type] || 0;
    if (w <= 0) continue;
    for (const reg of new Set([region, 'ALL'])) {
      batchStmts.push(
        env.DB.prepare(
          `INSERT INTO product_daily_stats (day, product_id, region, points)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(day, product_id, region) DO UPDATE SET
             points = points + excluded.points`
        ).bind(today, e.product_id, reg, w)
      );
    }
  }

  for (const e of enriched) {
    if (e.type !== 'not_interested' || !e.product_id) continue;
    batchStmts.push(
      env.DB.prepare(
        `INSERT INTO product_dismissals (owner_key, product_id, created_at)
         VALUES (?, ?, ?)
         ON CONFLICT(owner_key, product_id) DO NOTHING`
      ).bind(owner.ownerKey, e.product_id, now)
    );
  }

  if (batchStmts.length > 0) {
    await env.DB.batch(batchStmts);
  }

  return json({ stored: true, count: enriched.length }, 200, cors);
}

/* ------------------------------------------------------------------ */
/* POST /events/link                                                  */
/* ------------------------------------------------------------------ */

async function handleEventsLink(request, env, now, cors) {
  assertEnv(env, ['DB', 'HASH_SALT', 'FIREBASE_PROJECT_ID']);

  const user = await loadUserFromRequest(request, env, now);
  if (!user) throw new HttpError(401, 'unauthorized');
  const visitorId = validateVisitorId(request.headers.get('X-Visitor-Id'));
  if (!visitorId) throw new HttpError(400, 'visitor_id_required');

  const userKey = 'u:' + user.id;
  const visitorKey = 'v:' + visitorId;

  const visitorRows = await env.DB.prepare(
    'SELECT category_id, score, updated_at FROM user_interests WHERE owner_key = ?'
  ).bind(visitorKey).all();

  const rows = visitorRows.results || [];
  if (rows.length === 0) {
    const dismissals = await env.DB.prepare(
      'SELECT product_id FROM product_dismissals WHERE owner_key = ?'
    ).bind(visitorKey).all();
    const dRows = dismissals.results || [];
    if (dRows.length > 0) {
      const batchStmts = [];
      for (const d of dRows) {
        batchStmts.push(
          env.DB.prepare(
            `INSERT INTO product_dismissals (owner_key, product_id, created_at)
             VALUES (?, ?, ?)
             ON CONFLICT(owner_key, product_id) DO NOTHING`
          ).bind(userKey, d.product_id, now)
        );
      }
      batchStmts.push(
        env.DB.prepare('DELETE FROM product_dismissals WHERE owner_key = ?').bind(visitorKey)
      );
      await env.DB.batch(batchStmts);
    }
    return json({ merged: 0 }, 200, cors);
  }

  const userRows = await env.DB.prepare(
    'SELECT category_id, score, updated_at FROM user_interests WHERE owner_key = ?'
  ).bind(userKey).all();
  const userMap = new Map();
  for (const r of userRows.results || []) {
    userMap.set(r.category_id, { score: Number(r.score), updated_at: Number(r.updated_at) });
  }

  const batchStmts = [];
  let merged = 0;
  for (const v of rows) {
    const userCur = userMap.get(v.category_id) || { score: 0, updated_at: now };
    const userDecayed = decayScore(userCur.score, Math.max(0, now - userCur.updated_at));
    const visitorDecayed = decayScore(Number(v.score), Math.max(0, now - Number(v.updated_at)));
    let next = userDecayed + visitorDecayed;
    if (next > INTEREST_CAP) next = INTEREST_CAP;
    if (next < 0) next = 0;

    batchStmts.push(
      env.DB.prepare(
        `INSERT INTO user_interests (owner_key, category_id, score, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(owner_key, category_id) DO UPDATE SET
           score = excluded.score,
           updated_at = excluded.updated_at`
      ).bind(userKey, v.category_id, next, now)
    );
    merged++;
  }

  const dismissals = await env.DB.prepare(
    'SELECT product_id FROM product_dismissals WHERE owner_key = ?'
  ).bind(visitorKey).all();
  for (const d of dismissals.results || []) {
    batchStmts.push(
      env.DB.prepare(
        `INSERT INTO product_dismissals (owner_key, product_id, created_at)
         VALUES (?, ?, ?)
         ON CONFLICT(owner_key, product_id) DO NOTHING`
      ).bind(userKey, d.product_id, now)
    );
  }

  batchStmts.push(
    env.DB.prepare('DELETE FROM user_interests WHERE owner_key = ?').bind(visitorKey)
  );
  batchStmts.push(
    env.DB.prepare('DELETE FROM product_dismissals WHERE owner_key = ?').bind(visitorKey)
  );

  await env.DB.batch(batchStmts);
  return json({ merged }, 200, cors);
}

/* ------------------------------------------------------------------ */
/* POST /interests/picker                                             */
/* ------------------------------------------------------------------ */

async function handleInterestPicker(request, env, now, cors) {
  assertEnv(env, ['DB', 'FIREBASE_PROJECT_ID']);

  const user = await loadUserFromRequest(request, env, now);
  const owner = resolveOwner(request, user);
  if (!owner) throw new HttpError(400, 'visitor_id_required');
  if (hasPrivacyHeader(request)) throw new HttpError(403, 'privacy_header');

  const body = await readJson(request);
  if (!Array.isArray(body.category_ids) || body.category_ids.length < 1 || body.category_ids.length > 3) {
    throw new HttpError(400, 'invalid_category_ids');
  }
  const catIds = [];
  for (const cid of body.category_ids) {
    if (typeof cid !== 'string' || cid.length === 0 || cid.length > 64) {
      throw new HttpError(400, 'invalid_category_id');
    }
    catIds.push(cid);
  }
  const placeholders = catIds.map(() => '?').join(',');
  const catRows = await env.DB.prepare(
    `SELECT id FROM categories WHERE id IN (${placeholders})`
  ).bind(...catIds).all();
  const found = new Set((catRows.results || []).map((r) => r.id));
  for (const cid of catIds) {
    if (!found.has(cid)) throw new HttpError(400, 'invalid_category_id');
  }

  const existing = await env.DB.prepare(
    `SELECT category_id, score, updated_at FROM user_interests
     WHERE owner_key = ? AND category_id IN (${placeholders})`
  ).bind(owner.ownerKey, ...catIds).all();
  const existMap = new Map();
  for (const r of existing.results || []) {
    existMap.set(r.category_id, { score: Number(r.score), updated_at: Number(r.updated_at) });
  }

  const batchStmts = [];
  batchStmts.push(
    env.DB.prepare(
      `INSERT INTO picker_usage (owner_key, used_at)
       SELECT ?, ?
       WHERE NOT EXISTS (SELECT 1 FROM picker_usage WHERE owner_key = ?)`
    ).bind(owner.ownerKey, now, owner.ownerKey)
  );

  for (const cid of catIds) {
    const cur = existMap.get(cid) || { score: 0, updated_at: now };
    const decayed = decayScore(cur.score, Math.max(0, now - cur.updated_at));
    let next = decayed + 10;
    if (next > INTEREST_CAP) next = INTEREST_CAP;
    batchStmts.push(
      env.DB.prepare(
        `INSERT INTO user_interests (owner_key, category_id, score, updated_at)
         SELECT ?, ?, ?, ?
         WHERE EXISTS (SELECT 1 FROM picker_usage WHERE owner_key = ? AND used_at = ?)
         ON CONFLICT(owner_key, category_id) DO UPDATE SET
           score = excluded.score, updated_at = excluded.updated_at`
      ).bind(owner.ownerKey, cid, next, now, owner.ownerKey, now)
    );
  }

  const results = await env.DB.batch(batchStmts);
  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(409, 'picker_already_used');
  }

  return json({ ok: true, applied: catIds.length }, 200, cors);
}

/* ------------------------------------------------------------------ */
/* Internal handlers                                                  */
/* ------------------------------------------------------------------ */

async function requireInternal(request, env) {
  if (request.headers.get('Origin')) throw new HttpError(403, 'forbidden');
  assertEnv(env, ['DB', 'INTERNAL_KEY']);
  const provided = request.headers.get('X-Internal-Key') || '';
  if (!timingSafeEqual(provided, env.INTERNAL_KEY)) {
    throw new HttpError(401, 'unauthorized');
  }
}

async function handleInternalEvent(request, env, now) {
  await requireInternal(request, env);
  const body = await readJson(request);

  if (typeof body.user_id !== 'string' || body.user_id.length === 0 || body.user_id.length >= MAX_ID_LENGTH) {
    throw new HttpError(400, 'invalid_user_id');
  }
  if (typeof body.type !== 'string' || !INTERNAL_EVENT_TYPES.has(body.type)) {
    throw new HttpError(400, 'invalid_event_type');
  }
  if (typeof body.product_id !== 'string' || body.product_id.length === 0 || body.product_id.length >= MAX_ID_LENGTH) {
    throw new HttpError(400, 'invalid_product_id');
  }
  if (typeof body.ref !== 'string' || body.ref.length === 0 || body.ref.length > 128) {
    throw new HttpError(400, 'invalid_ref');
  }
  const region = typeof body.region === 'string' && body.region.length > 0 && body.region.length <= 32
    ? body.region
    : 'ALL';

  const product = await env.DB.prepare(
    `SELECT p.id, p.business_id, p.category_id
     FROM products p JOIN businesses b ON b.id = p.business_id
     WHERE p.id = ? AND p.status = 'active' AND b.approval_status = 'approved' LIMIT 1`
  ).bind(body.product_id).first();
  if (!product) throw new HttpError(404, 'product_not_found');

  const ownerKey = 'u:' + body.user_id;
  const weight = EVENT_WEIGHTS[body.type];
  const today = Math.floor(now / 86400);

  const cur = await env.DB.prepare(
    `SELECT score, updated_at FROM user_interests
     WHERE owner_key = ? AND category_id = ? LIMIT 1`
  ).bind(ownerKey, product.category_id).first();

  const decayed = decayScore(Number(cur?.score || 0), Math.max(0, now - Number(cur?.updated_at || now)));
  let next = decayed + weight;
  if (next > INTEREST_CAP) next = INTEREST_CAP;
  if (next < 0) next = 0;

  const eventId = generateId('evt_');
  const batchStmts = [
    env.DB.prepare(
      `INSERT INTO events
         (id, owner_key, user_id, visitor_id, type, product_id, business_id,
          category_id, query, region, ip_hash, ref, created_at)
       SELECT ?, ?, ?, NULL, ?, ?, ?, ?, NULL, ?, NULL, ?, ?
       WHERE NOT EXISTS (
         SELECT 1 FROM events WHERE user_id = ? AND type = ? AND product_id = ? AND ref = ?
       )`
    ).bind(
      eventId, ownerKey, body.user_id, body.type, product.id, product.business_id,
      product.category_id, region, body.ref, now,
      body.user_id, body.type, product.id, body.ref
    ),
    env.DB.prepare(
      `INSERT INTO user_interests (owner_key, category_id, score, updated_at)
       SELECT ?, ?, ?, ?
       WHERE EXISTS (SELECT 1 FROM events WHERE id = ?)
       ON CONFLICT(owner_key, category_id) DO UPDATE SET
         score = excluded.score, updated_at = excluded.updated_at`
    ).bind(ownerKey, product.category_id, next, now, eventId),
    env.DB.prepare(
      `UPDATE user_interests SET score = ?, updated_at = ?
       WHERE owner_key = ? AND category_id = ?
         AND EXISTS (SELECT 1 FROM events WHERE id = ?)`
    ).bind(next, now, ownerKey, product.category_id, eventId),
  ];
  for (const reg of new Set([region, 'ALL'])) {
    batchStmts.push(
      env.DB.prepare(
        `INSERT INTO product_daily_stats (day, product_id, region, points)
         SELECT ?, ?, ?, ?
         WHERE EXISTS (SELECT 1 FROM events WHERE id = ?)
         ON CONFLICT(day, product_id, region) DO UPDATE SET points = points + excluded.points`
      ).bind(today, product.id, reg, weight, eventId)
    );
  }

  const results = await env.DB.batch(batchStmts);
  const stored = (results[0]?.meta?.changes ?? 0) === 1;
  if (!stored) {
    const exists = await env.DB.prepare(
      `SELECT 1 FROM events WHERE user_id = ? AND type = ? AND product_id = ? AND ref = ? LIMIT 1`
    ).bind(body.user_id, body.type, product.id, body.ref).first();
    if (!exists) throw new HttpError(500, 'insert_failed');
  }

  return json({ stored, duplicate: !stored }, 200, {});
}

async function handleInternalPurge(request, env, now) {
  await requireInternal(request, env);

  const cutoffEvents = now - PURGE_EVENTS_DAYS * 86400;
  const cutoffStats = now - PURGE_STATS_DAYS * 86400;
  const cutoffVisitorInterests = now - PURGE_VISITOR_INTERESTS_DAYS * 86400;
  const statsCutoffDay = Math.floor(cutoffStats / 86400);

  const r = await env.DB.batch([
    env.DB.prepare(
      `DELETE FROM events WHERE id IN (
         SELECT id FROM events WHERE created_at < ? LIMIT ?
       )`
    ).bind(cutoffEvents, PURGE_CHUNK),
    env.DB.prepare(
      `DELETE FROM product_daily_stats WHERE day < ?`
    ).bind(statsCutoffDay),
    env.DB.prepare(
      `DELETE FROM user_interests WHERE owner_key LIKE 'v:%' AND updated_at < ?
       AND owner_key NOT IN (SELECT DISTINCT owner_key FROM events WHERE created_at > ?)`
    ).bind(cutoffVisitorInterests, cutoffVisitorInterests),
  ]);

  const deletedEvents = r[0]?.meta?.changes ?? 0;
  const deletedStats = r[1]?.meta?.changes ?? 0;
  const deletedVisitorInterests = r[2]?.meta?.changes ?? 0;

  const more = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM events WHERE created_at < ?'
  ).bind(cutoffEvents).first();

  return json(
    {
      deleted_events: deletedEvents,
      deleted_stats: deletedStats,
      deleted_visitor_interests: deletedVisitorInterests,
      more_events_pending: Number(more?.n || 0) > 0,
    },
    200,
    {}
  );
}

/* ------------------------------------------------------------------ */
/* Router                                                             */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request, env) {
    const now = Math.floor(Date.now() / 1000);
    const origin = request.headers.get('Origin');

    if (origin && !isAllowedOrigin(origin)) {
      return json({ error: 'origin_not_allowed' }, 403, {});
    }

    const cors = corsHeaders(origin);
    const url = new URL(request.url);
    const path = url.pathname;

    if (path.startsWith('/internal/') && origin) {
      return json({ error: 'forbidden' }, 403, {});
    }

    if (request.method === 'OPTIONS') {
      if (path.startsWith('/internal/')) {
        return json({ error: 'forbidden' }, 403, {});
      }
      return new Response(null, {
        status: 204,
        headers: {
          ...cors,
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        },
      });
    }

    try {
      if (path === '/health' && request.method === 'GET') {
        return await handleHealth(env, now, cors);
      }
      if (path === '/chips' && request.method === 'GET') {
        return await handleChips(env, cors);
      }
      if (path === '/feed' && request.method === 'GET') {
        return await handleFeed(request, env, now, cors);
      }
      if (path === '/search' && request.method === 'GET') {
        return await handleSearch(request, env, now, cors);
      }
      if (path === '/search/suggest' && request.method === 'GET') {
        return await handleSuggest(request, env, now, cors);
      }
      if (path === '/events' && request.method === 'POST') {
        return await handlePostEvents(request, env, now, cors);
      }
      if (path === '/events/link' && request.method === 'POST') {
        return await handleEventsLink(request, env, now, cors);
      }
      if (path === '/interests/picker' && request.method === 'POST') {
        return await handleInterestPicker(request, env, now, cors);
      }
      if (path === '/internal/event' && request.method === 'POST') {
        return await handleInternalEvent(request, env, now);
      }
      if (path === '/internal/purge-events' && request.method === 'POST') {
        return await handleInternalPurge(request, env, now);
      }

      const knownPaths = [
        '/health','/chips','/feed','/search','/search/suggest',
        '/events','/events/link','/interests/picker',
        '/internal/event','/internal/purge-events',
      ];
      if (knownPaths.includes(path)) {
        return json({ error: 'method_not_allowed' }, 405, cors);
      }
      return json({ error: 'not_found' }, 404, cors);
    } catch (err) {
      if (err instanceof HttpError) {
        return json({ error: err.code, ...(err.extra || {}) }, err.status, cors);
      }
      console.error('unhandled_error', { name: err?.name, message: err?.message });
      return json({ error: 'server_error' }, 500, cors);
    }
  },
};
