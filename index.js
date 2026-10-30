/**
 * earnity-catalog — Cloudflare Worker
 * Businesses, products, categories, offers, commissions, referee slots.
 * Does NOT do feed, search, click tracking, orders, payments, wallets or admin.
 *
 * Bindings: DB (D1), FIREBASE_PROJECT_ID, HASH_SALT, INTERNAL_KEY
 * Deployed via GitHub → Cloudflare Workers Builds.
 */

const JWKS_URL =
  'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const ALLOWED_HOST = 'earnityug.com';

/* -------------------- EDIT THESE STARTING VALUES -------------------- */
const BASIC_MAX_ACTIVE_PRODUCTS = 200;
const BASIC_MAX_PRICE_UGX = 1_000_000;
const BASIC_MAX_DELIVERY_DAYS = 14;
const ABSOLUTE_MAX_PRICE_UGX = 25_000_000;
/* ------------------------------------------------------------------- */

const SLOT_TTL_SECONDS = 7 * 86400;
const OFFER_MAX_SPAN_SECONDS = 30 * 86400;
const MAX_BODY_BYTES = 8192;
const MAX_ID_LENGTH = 128;
const MAX_SUBDOMAIN_LENGTH = 30;
const MIN_SUBDOMAIN_LENGTH = 3;
const MAX_PAGE_LIMIT = 20;
const CLOCK_SKEW_SECONDS = 60;
const JWKS_CACHE_SECONDS = 3600;
const KEY_CACHE_MS = 3600_000;
const MAX_TURNSTILE_TOKEN_LENGTH = 2048;
const MAX_SUB_LENGTH = 128;
const PUBLIC_CACHE_SECONDS = 30;
const MAX_IMAGES = 6;
const MIN_COMMISSION_BPS = 100;
const MIN_REFERRER_BPS = 100;
const PUBLIC_TERMS_VERSION = 'catalog-terms-2026-10';

const RESERVED_SUBDOMAINS = new Set([
  'www','api','admin','mail','support','help','earnity','root','system',
  'staff','verify','catalog','site','orders','payments','payouts','notify',
  'cron','ledger',
]);

const CLOUDINARY_ID_RE = /^[a-zA-Z0-9_\-\/]{1,200}$/;
const SUBDOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])?$/;
const URL_RE = /^https?:\/\/[^\s<>"']{1,480}$/;

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

function publicJson(data, status, cors) {
  return json(data, status, cors, {
    'Cache-Control': `public, max-age=${PUBLIC_CACHE_SECONDS}`,
  });
}

function corsHeaders(origin) {
  if (!origin) return { Vary: 'Origin' };
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
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
/* Firebase ID token verification                                     */
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

async function requireAuth(request, env, now) {
  const auth = request.headers.get('Authorization');
  if (!auth) throw new HttpError(401, 'unauthorized');
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
  )
    .bind(payload.sub)
    .first();
  if (!user) throw new HttpError(404, 'not_registered');
  if (user.status === 'blocked') throw new HttpError(403, 'account_blocked');
  return { user, payload };
}

function requireAccountType(user, expected) {
  if (user.account_type !== expected) {
    throw new HttpError(403, 'wrong_account_type');
  }
}

function requireAdmin(user) {
  // Not exposed by this Worker; only internal key auth is used.
  if (!user) throw new HttpError(403, 'forbidden');
}

/* ------------------------------------------------------------------ */
/* Audit helper                                                       */
/* ------------------------------------------------------------------ */

function auditStmt(env, id, actorId, action, targetType, targetId, metadata, ipHash, now) {
  return env.DB.prepare(
    `INSERT INTO audit_log
       (id, actor_user_id, action, target_type, target_id, metadata, ip_hash, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    id,
    actorId,
    action,
    targetType,
    targetId,
    JSON.stringify(metadata || {}),
    ipHash,
    now
  );
}

/* ------------------------------------------------------------------ */
/* Validation                                                         */
/* ------------------------------------------------------------------ */

function assertId(value, code) {
  if (typeof value !== 'string' || value.length === 0 || value.length >= MAX_ID_LENGTH) {
    throw new HttpError(400, code || 'invalid_id');
  }
  return value;
}

function assertString(value, { min = 0, max, code } = {}) {
  if (typeof value !== 'string') throw new HttpError(400, code || 'invalid_string');
  if (value.length < min || (max != null && value.length > max)) {
    throw new HttpError(400, code || 'invalid_string');
  }
  return value;
}

function assertInt(value, { min, max, code } = {}) {
  if (!Number.isInteger(value)) throw new HttpError(400, code || 'invalid_integer');
  if (min != null && value < min) throw new HttpError(400, code || 'invalid_integer');
  if (max != null && value > max) throw new HttpError(400, code || 'invalid_integer');
  return value;
}

function validateSubdomain(input) {
  if (typeof input !== 'string') throw new HttpError(400, 'invalid_subdomain');
  const s = input.toLowerCase().trim();
  if (s.length < MIN_SUBDOMAIN_LENGTH || s.length > MAX_SUBDOMAIN_LENGTH) {
    throw new HttpError(400, 'invalid_subdomain');
  }
  if (!SUBDOMAIN_RE.test(s)) throw new HttpError(400, 'invalid_subdomain');
  if (s.startsWith('-') || s.endsWith('-')) throw new HttpError(400, 'invalid_subdomain');
  if (RESERVED_SUBDOMAINS.has(s)) throw new HttpError(409, 'subdomain_reserved');
  return s;
}

function validateImageIds(ids) {
  if (!Array.isArray(ids)) throw new HttpError(400, 'invalid_images');
  if (ids.length > MAX_IMAGES) throw new HttpError(400, 'invalid_images');
  const out = [];
  for (const id of ids) {
    if (typeof id !== 'string' || !CLOUDINARY_ID_RE.test(id)) {
      throw new HttpError(400, 'invalid_images');
    }
    out.push(id);
  }
  return out;
}

function validateOnlineUrl(url) {
  if (url === null || url === undefined || url === '') return null;
  if (typeof url !== 'string' || !URL_RE.test(url)) {
    throw new HttpError(400, 'invalid_url');
  }
  return url;
}

function checkCloudinaryId(value, code) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value !== 'string' || !CLOUDINARY_ID_RE.test(value)) {
    throw new HttpError(400, code);
  }
  return value;
}

/* ------------------------------------------------------------------ */
/* Effective price / cap helpers                                      */
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

async function loadPlatformSettings(env) {
  const rows = await env.DB.prepare(
    'SELECT key, value_int FROM platform_settings WHERE key IN (?, ?, ?)'
  )
    .bind('earnity_bps', 'seller_reserve_bps', 'deposit_cap_bps')
    .all();
  const map = { earnity_bps: 1000, seller_reserve_bps: 500, deposit_cap_bps: 4800 };
  for (const r of rows.results || []) map[r.key] = Number(r.value_int);
  return map;
}

/* ------------------------------------------------------------------ */
/* Public handlers                                                    */
/* ------------------------------------------------------------------ */

async function handleHealth(env, now, cors) {
  return json({ ok: true, service: 'earnity-catalog', time: now }, 200, cors);
}

async function handleCategories(env, cors) {
  const rows = await env.DB.prepare(
    'SELECT id, name, sort_order FROM categories ORDER BY sort_order ASC, name ASC'
  ).all();
  return publicJson({ categories: rows.results || [] }, 200, cors);
}

async function loadPublicBusinessCard(env, businessId) {
  return env.DB.prepare(
    `SELECT id, name, subdomain, description, logo_public_id, banner_public_id,
            category_id, delivery_text, default_delivery_days, level, delivered_sales, tier
     FROM businesses
     WHERE id = ? AND approval_status = 'approved'`
  ).bind(businessId).first();
}

function mapPublicProduct(product, business, slotsFree, now) {
  const { price, offer_active } = effectivePrice(product, now);
  let imageIds = [];
  try { imageIds = JSON.parse(product.image_ids || '[]'); } catch { imageIds = []; }
  return {
    id: product.id,
    name: product.name,
    description: product.description,
    price_ugx: Number(product.price_ugx),
    effective_price_ugx: price,
    offer_active,
    offer_ends_at: offer_active ? Number(product.offer_ends_at) : null,
    images: imageIds,
    category_id: product.category_id,
    commission_bps: Number(product.commission_bps),
    delivery_text: product.delivery_text,
    delivery_days: Number(product.delivery_days),
    business: business
      ? {
          id: business.id,
          name: business.name,
          subdomain: business.subdomain,
          logo_public_id: business.logo_public_id,
          banner_public_id: business.banner_public_id,
          level: Number(business.level),
          delivered_sales: Number(business.delivered_sales),
        }
      : null,
    slots_free: Math.max(0, slotsFree),
  };
}

async function handlePublicProduct(env, productId, now, cors) {
  assertEnv(env, ['DB']);
  if (typeof productId !== 'string' || productId.length === 0 || productId.length >= MAX_ID_LENGTH) {
    throw new HttpError(400, 'invalid_id');
  }
  const product = await env.DB.prepare(
    `SELECT * FROM products WHERE id = ? AND status = 'active' LIMIT 1`
  ).bind(productId).first();
  if (!product) throw new HttpError(404, 'product_not_found');

  const business = await loadPublicBusinessCard(env, product.business_id);
  if (!business) throw new HttpError(404, 'product_not_found');

  const used = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM product_referee_slots
     WHERE product_id = ? AND status IN ('pending','active')`
  ).bind(product.id).first();
  const slotsFree = Math.max(0, Number(product.referee_max) - Number(used?.n || 0));

  return publicJson(
    mapPublicProduct(product, business, slotsFree, now),
    200,
    cors
  );
}

async function handlePublicStore(env, subdomain, url, now, cors) {
  assertEnv(env, ['DB']);
  if (typeof subdomain !== 'string' || subdomain.length < 3 || subdomain.length > 30) {
    throw new HttpError(400, 'invalid_subdomain');
  }
  const business = await env.DB.prepare(
    `SELECT id, name, subdomain, description, logo_public_id, banner_public_id,
            category_id, delivery_text, default_delivery_days, level, delivered_sales, tier
     FROM businesses
     WHERE subdomain = ? COLLATE NOCASE AND approval_status = 'approved'`
  ).bind(subdomain).first();
  if (!business) throw new HttpError(404, 'store_not_found');

  // Cursor = created_at of last item; encoded as integer string.
  const cursorParam = url.searchParams.get('cursor') || '';
  let cursor = 0;
  if (cursorParam) {
    const n = Number(cursorParam);
    if (!Number.isInteger(n) || n < 0) throw new HttpError(400, 'invalid_cursor');
    cursor = n;
  }
  const limit = MAX_PAGE_LIMIT;

  const rows = await env.DB.prepare(
    `SELECT * FROM products
     WHERE business_id = ? AND status = 'active' AND created_at < ?
     ORDER BY created_at DESC
     LIMIT ?`
  ).bind(business.id, cursor || 9999999999, limit + 1).all();

  const results = rows.results || [];
  const hasMore = results.length > limit;
  const page = results.slice(0, limit);

  // slot-free counts per product for this page
  const productIds = page.map((p) => p.id);
  const slotCounts = {};
  if (productIds.length > 0) {
    const placeholders = productIds.map(() => '?').join(',');
    const slotRows = await env.DB.prepare(
      `SELECT product_id, COUNT(*) AS n FROM product_referee_slots
       WHERE status IN ('pending','active') AND product_id IN (${placeholders})
       GROUP BY product_id`
    ).bind(...productIds).all();
    for (const r of slotRows.results || []) slotCounts[r.product_id] = Number(r.n);
  }

  const items = page.map((p) => {
    const used = slotCounts[p.id] || 0;
    const slotsFree = Math.max(0, Number(p.referee_max) - used);
    return mapPublicProduct(p, business, slotsFree, now);
  });

  const nextCursor = hasMore ? Number(page[page.length - 1].created_at) : null;

  return publicJson(
    { business: {
        id: business.id,
        name: business.name,
        subdomain: business.subdomain,
        description: business.description,
        logo_public_id: business.logo_public_id,
        banner_public_id: business.banner_public_id,
        category_id: business.category_id,
        delivery_text: business.delivery_text,
        default_delivery_days: Number(business.default_delivery_days),
        level: Number(business.level),
        delivered_sales: Number(business.delivered_sales),
        tier: business.tier,
      },
      products: items,
      next_cursor: nextCursor,
    },
    200,
    cors
  );
}

/* ------------------------------------------------------------------ */
/* Seller handlers                                                    */
/* ------------------------------------------------------------------ */

async function requireSeller(request, env, now) {
  const { user } = await requireAuth(request, env, now);
  requireAccountType(user, 'seller');
  return user;
}

async function loadOwnedBusiness(env, userId) {
  return env.DB.prepare('SELECT * FROM businesses WHERE owner_user_id = ? LIMIT 1')
    .bind(userId).first();
}

function publicBusinessLimits() {
  return {
    tier: 'basic',
    max_active_products: BASIC_MAX_ACTIVE_PRODUCTS,
    max_price_ugx: BASIC_MAX_PRICE_UGX,
    max_delivery_days: BASIC_MAX_DELIVERY_DAYS,
    absolute_max_price_ugx: ABSOLUTE_MAX_PRICE_UGX,
  };
}

async function handleCreateBusiness(request, env, now, cors) {
  assertEnv(env, ['DB', 'HASH_SALT', 'FIREBASE_PROJECT_ID']);
  const user = await requireSeller(request, env, now);
  const body = await readJson(request);

  if (body.accept_seller_terms !== true) {
    throw new HttpError(400, 'terms_not_accepted');
  }

  const name = assertString(body.name, { min: 2, max: 120, code: 'invalid_name' });
  const subdomain = validateSubdomain(body.subdomain);
  const description = assertString(body.description ?? '', { max: 1000, code: 'invalid_description' });
  const categoryId = assertId(body.category_id, 'invalid_category');
  const deliveryText = assertString(body.delivery_text ?? '', { max: 300, code: 'invalid_delivery_text' });
  const defaultDeliveryDays = assertInt(body.default_delivery_days, {
    min: 1, max: BASIC_MAX_DELIVERY_DAYS, code: 'invalid_delivery_days',
  });
  const addressText = assertString(body.address_text ?? '', { max: 500, code: 'invalid_address' });
  const onlineUrl = validateOnlineUrl(body.online_presence_url);

  // category must exist
  const cat = await env.DB.prepare('SELECT id FROM categories WHERE id = ? LIMIT 1')
    .bind(categoryId).first();
  if (!cat) throw new HttpError(400, 'invalid_category');

  // referrer lookup (optional)
  let referrerUserId = null;
  let referrerBps = 0;
  if (body.referrer_username != null && body.referrer_username !== '') {
    const uname = assertString(body.referrer_username, { min: 1, max: 60, code: 'invalid_referrer_username' });
    const ref = await env.DB.prepare(
      'SELECT user_id FROM referee_usernames WHERE username = ? COLLATE NOCASE LIMIT 1'
    ).bind(uname).first();
    if (!ref) throw new HttpError(400, 'referrer_not_found');
    if (ref.user_id === user.id) throw new HttpError(400, 'referrer_is_owner');
    referrerUserId = ref.user_id;
    referrerBps = MIN_REFERRER_BPS;
  }

  const ipHash = await hmacHex(env, 'ip:' + (request.headers.get('CF-Connecting-IP') || ''));
  const businessId = generateId('biz_');
  const auditId = generateId('aud_');

  const insertStmt = env.DB.prepare(
    `INSERT INTO businesses
       (id, owner_user_id, name, subdomain, description, category_id, delivery_text,
        default_delivery_days, address_text, online_presence_url, terms_version,
        referrer_user_id, referrer_bps, created_at, updated_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
     WHERE NOT EXISTS (SELECT 1 FROM businesses WHERE owner_user_id = ?)`
  ).bind(
    businessId,
    user.id,
    name,
    subdomain,
    description,
    categoryId,
    deliveryText,
    defaultDeliveryDays,
    addressText,
    onlineUrl,
    PUBLIC_TERMS_VERSION,
    referrerUserId,
    referrerBps,
    now,
    now,
    user.id
  );

  let results;
  try {
    results = await env.DB.batch([
      insertStmt,
      env.DB.prepare(
        `INSERT INTO audit_log
           (id, actor_user_id, action, target_type, target_id, metadata, ip_hash, created_at)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?
         WHERE EXISTS (SELECT 1 FROM businesses WHERE id = ? AND owner_user_id = ?)`
      ).bind(
        auditId,
        user.id,
        'business_created',
        'business',
        businessId,
        JSON.stringify({ subdomain, category_id: categoryId, has_referrer: referrerUserId !== null }),
        ipHash,
        now,
        businessId,
        user.id
      ),
    ]);
  } catch (err) {
    const msg = String(err?.message || '');
    if (msg.includes('UNIQUE') && msg.toLowerCase().includes('subdomain')) {
      throw new HttpError(409, 'subdomain_taken');
    }
    if (msg.includes('UNIQUE')) {
      throw new HttpError(409, 'business_exists');
    }
    if (msg.includes('referrer_user_id_immutable') || msg.includes('referrer_bps')) {
      throw new HttpError(400, 'invalid_referrer');
    }
    throw err;
  }

  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(409, 'business_exists');
  }

  const created = await loadOwnedBusiness(env, user.id);

  return json(
    {
      business: {
        id: created.id,
        name: created.name,
        subdomain: created.subdomain,
        description: created.description,
        category_id: created.category_id,
        delivery_text: created.delivery_text,
        default_delivery_days: Number(created.default_delivery_days),
        approval_status: created.approval_status,
        tier: created.tier,
        referrer_bps: Number(created.referrer_bps),
        has_referrer: created.referrer_user_id != null,
        level: Number(created.level),
        delivered_sales: Number(created.delivered_sales),
      },
      limits: publicBusinessLimits(),
    },
    201,
    cors
  );
}

async function handleGetMyBusiness(request, env, now, cors) {
  assertEnv(env, ['DB', 'FIREBASE_PROJECT_ID']);
  const user = await requireSeller(request, env, now);
  const biz = await loadOwnedBusiness(env, user.id);
  if (!biz) throw new HttpError(404, 'business_not_found');

  const counts = await env.DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM products WHERE business_id = ?) AS product_count,
       (SELECT COUNT(*) FROM products WHERE business_id = ? AND status = 'active') AS active_product_count`
  ).bind(biz.id, biz.id).first();

  return json(
    {
      business: {
        id: biz.id,
        name: biz.name,
        subdomain: biz.subdomain,
        description: biz.description,
        logo_public_id: biz.logo_public_id,
        banner_public_id: biz.banner_public_id,
        category_id: biz.category_id,
        delivery_text: biz.delivery_text,
        default_delivery_days: Number(biz.default_delivery_days),
        level: Number(biz.level),
        delivered_sales: Number(biz.delivered_sales),
        tier: biz.tier,
        approval_status: biz.approval_status,
        address_text: biz.address_text,
        online_presence_url: biz.online_presence_url,
        approval_note: biz.approval_note,
        terms_version: biz.terms_version,
        referrer_bps: Number(biz.referrer_bps),
        has_referrer: biz.referrer_user_id != null,
        discovery_until: biz.discovery_until,
        created_at: Number(biz.created_at),
        updated_at: Number(biz.updated_at),
        product_count: Number(counts?.product_count || 0),
        active_product_count: Number(counts?.active_product_count || 0),
      },
      limits: publicBusinessLimits(),
    },
    200,
    cors
  );
}

async function handlePatchMyBusiness(request, env, now, cors) {
  assertEnv(env, ['DB', 'HASH_SALT', 'FIREBASE_PROJECT_ID']);
  const user = await requireSeller(request, env, now);
  const biz = await loadOwnedBusiness(env, user.id);
  if (!biz) throw new HttpError(404, 'business_not_found');
  const body = await readJson(request);

  const fields = {};
  if ('description' in body) {
    fields.description = assertString(body.description, { max: 1000, code: 'invalid_description' });
  }
  if ('logo_public_id' in body) {
    fields.logo_public_id = checkCloudinaryId(body.logo_public_id, 'invalid_logo');
  }
  if ('banner_public_id' in body) {
    fields.banner_public_id = checkCloudinaryId(body.banner_public_id, 'invalid_banner');
  }
  if ('delivery_text' in body) {
    fields.delivery_text = assertString(body.delivery_text, { max: 300, code: 'invalid_delivery_text' });
  }
  if ('default_delivery_days' in body) {
    fields.default_delivery_days = assertInt(body.default_delivery_days, {
      min: 1, max: BASIC_MAX_DELIVERY_DAYS, code: 'invalid_delivery_days',
    });
  }
  if ('category_id' in body) {
    const cid = assertId(body.category_id, 'invalid_category');
    const cat = await env.DB.prepare('SELECT id FROM categories WHERE id = ? LIMIT 1')
      .bind(cid).first();
    if (!cat) throw new HttpError(400, 'invalid_category');
    fields.category_id = cid;
  }
  if ('address_text' in body) {
    fields.address_text = assertString(body.address_text ?? '', { max: 500, code: 'invalid_address' });
  }
  if ('online_presence_url' in body) {
    fields.online_presence_url = validateOnlineUrl(body.online_presence_url);
  }

  // Guarded UPDATE: ownership in WHERE.
  let results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE businesses SET
         description = COALESCE(?, description),
         logo_public_id = CASE WHEN ? = 1 THEN ? ELSE logo_public_id END,
         banner_public_id = CASE WHEN ? = 1 THEN ? ELSE banner_public_id END,
         delivery_text = COALESCE(?, delivery_text),
         default_delivery_days = COALESCE(?, default_delivery_days),
         category_id = COALESCE(?, category_id),
         address_text = COALESCE(?, address_text),
         online_presence_url = CASE WHEN ? = 1 THEN ? ELSE online_presence_url END,
         updated_at = ?
       WHERE owner_user_id = ?`
    ).bind(
      fields.description ?? null,
      'logo_public_id' in fields ? 1 : 0,
      fields.logo_public_id ?? null,
      'banner_public_id' in fields ? 1 : 0,
      fields.banner_public_id ?? null,
      fields.delivery_text ?? null,
      fields.default_delivery_days ?? null,
      fields.category_id ?? null,
      fields.address_text ?? null,
      'online_presence_url' in fields ? 1 : 0,
      fields.online_presence_url ?? null,
      now,
      user.id
    ),
    env.DB.prepare(
      `INSERT INTO audit_log
         (id, actor_user_id, action, target_type, target_id, metadata, ip_hash, created_at)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?
       WHERE EXISTS (SELECT 1 FROM businesses WHERE id = ? AND owner_user_id = ?)`
    ).bind(
      generateId('aud_'),
      user.id,
      'business_updated',
      'business',
      biz.id,
      JSON.stringify({ keys: Object.keys(fields) }),
      await hmacHex(env, 'ip:' + (request.headers.get('CF-Connecting-IP') || '')),
      now,
      biz.id,
      user.id
    ),
  ]);

  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(404, 'business_not_found');
  }

  const updated = await loadOwnedBusiness(env, user.id);
  return json(
    {
      business: {
        id: updated.id,
        name: updated.name,
        subdomain: updated.subdomain,
        description: updated.description,
        logo_public_id: updated.logo_public_id,
        banner_public_id: updated.banner_public_id,
        category_id: updated.category_id,
        delivery_text: updated.delivery_text,
        default_delivery_days: Number(updated.default_delivery_days),
        address_text: updated.address_text,
        online_presence_url: updated.online_presence_url,
        updated_at: Number(updated.updated_at),
      },
    },
    200,
    cors
  );
}

async function handleRaiseReferrerRate(request, env, now, cors) {
  assertEnv(env, ['DB', 'HASH_SALT', 'FIREBASE_PROJECT_ID']);
  const user = await requireSeller(request, env, now);
  const biz = await loadOwnedBusiness(env, user.id);
  if (!biz) throw new HttpError(404, 'business_not_found');
  const body = await readJson(request);
  const newBps = assertInt(body.referrer_bps, { min: MIN_REFERRER_BPS, max: 5000, code: 'invalid_referrer_bps' });

  if (biz.referrer_user_id == null) throw new HttpError(400, 'no_referrer');
  if (newBps <= Number(biz.referrer_bps)) throw new HttpError(400, 'referrer_bps_not_raised');

  const settings = await loadPlatformSettings(env);

  // Highest commission among this business's products.
  const maxRow = await env.DB.prepare(
    'SELECT MAX(commission_bps) AS m FROM products WHERE business_id = ?'
  ).bind(biz.id).first();
  const maxCommission = Number(maxRow?.m || 0);
  const total = newBps + maxCommission + settings.earnity_bps + settings.seller_reserve_bps;
  if (total > settings.deposit_cap_bps) {
    throw new HttpError(400, 'deposit_cap_exceeded', {
      max_referrer_bps: settings.deposit_cap_bps - maxCommission - settings.earnity_bps - settings.seller_reserve_bps,
    });
  }

  const ipHash = await hmacHex(env, 'ip:' + (request.headers.get('CF-Connecting-IP') || ''));
  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE businesses SET referrer_bps = ?, updated_at = ?
       WHERE id = ? AND owner_user_id = ? AND referrer_user_id IS NOT NULL AND referrer_bps < ?`
    ).bind(newBps, now, biz.id, user.id, newBps),
    env.DB.prepare(
      `INSERT INTO audit_log
         (id, actor_user_id, action, target_type, target_id, metadata, ip_hash, created_at)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?
       WHERE EXISTS (SELECT 1 FROM businesses WHERE id = ? AND referrer_bps = ?)`
    ).bind(
      generateId('aud_'),
      user.id,
      'referrer_rate_raised',
      'business',
      biz.id,
      JSON.stringify({ old_bps: Number(biz.referrer_bps), new_bps: newBps }),
      ipHash,
      now,
      biz.id,
      newBps
    ),
  ]);

  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(409, 'referrer_bps_not_raised');
  }

  return json({ referrer_bps: newBps }, 200, cors);
}

async function loadProductOwned(env, productId, userId) {
  return env.DB.prepare(
    `SELECT p.*, b.owner_user_id, b.referrer_bps, b.default_delivery_days, b.approval_status
     FROM products p
     JOIN businesses b ON b.id = p.business_id
     WHERE p.id = ? AND b.owner_user_id = ? LIMIT 1`
  ).bind(productId, userId).first();
}

async function handleCreateProduct(request, env, now, cors) {
  assertEnv(env, ['DB', 'HASH_SALT', 'FIREBASE_PROJECT_ID']);
  const user = await requireSeller(request, env, now);
  const biz = await loadOwnedBusiness(env, user.id);
  if (!biz) throw new HttpError(404, 'business_not_found');
  const body = await readJson(request);

  const name = assertString(body.name, { min: 2, max: 120, code: 'invalid_name' });
  const description = assertString(body.description ?? '', { max: 2000, code: 'invalid_description' });
  const price = assertInt(body.price_ugx, { min: 1, max: ABSOLUTE_MAX_PRICE_UGX, code: 'invalid_price' });
  if (price > BASIC_MAX_PRICE_UGX) throw new HttpError(400, 'price_above_limit');
  const categoryId = assertId(body.category_id, 'invalid_category');
  const commissionBps = assertInt(body.commission_bps ?? MIN_COMMISSION_BPS, {
    min: MIN_COMMISSION_BPS, max: 4800, code: 'invalid_commission_bps',
  });
  const refereeMax = assertInt(body.referee_max ?? 5, { min: 1, max: 50, code: 'invalid_referee_max' });
  const deliveryText = assertString(body.delivery_text ?? '', { max: 300, code: 'invalid_delivery_text' });
  const deliveryDays = assertInt(
    body.delivery_days ?? Number(biz.default_delivery_days),
    { min: 1, max: BASIC_MAX_DELIVERY_DAYS, code: 'invalid_delivery_days' }
  );
  const imageIds = validateImageIds(body.image_ids ?? []);

  const cat = await env.DB.prepare('SELECT id FROM categories WHERE id = ? LIMIT 1')
    .bind(categoryId).first();
  if (!cat) throw new HttpError(400, 'invalid_category');

  // cap check
  const settings = await loadPlatformSettings(env);
  const totalBps = commissionBps + Number(biz.referrer_bps) + settings.earnity_bps + settings.seller_reserve_bps;
  if (totalBps > settings.deposit_cap_bps) {
    throw new HttpError(400, 'deposit_cap_exceeded', {
      max_commission_bps: settings.deposit_cap_bps - Number(biz.referrer_bps) - settings.earnity_bps - settings.seller_reserve_bps,
    });
  }

  const productId = generateId('prd_');
  const ipHash = await hmacHex(env, 'ip:' + (request.headers.get('CF-Connecting-IP') || ''));

  let results;
  try {
    results = await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO products
           (id, business_id, name, description, price_ugx, category_id, image_ids,
            commission_bps, referee_max, delivery_text, delivery_days, created_at, updated_at)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
         WHERE (SELECT COUNT(*) FROM products WHERE business_id = ? AND status = 'active') < ?`
      ).bind(
        productId, biz.id, name, description, price, categoryId, JSON.stringify(imageIds),
        commissionBps, refereeMax, deliveryText, deliveryDays, now, now,
        biz.id, BASIC_MAX_ACTIVE_PRODUCTS
      ),
      env.DB.prepare(
        `INSERT INTO audit_log
           (id, actor_user_id, action, target_type, target_id, metadata, ip_hash, created_at)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?
         WHERE EXISTS (SELECT 1 FROM products WHERE id = ?)`
      ).bind(
        generateId('aud_'),
        user.id,
        'product_created',
        'product',
        productId,
        JSON.stringify({ business_id: biz.id, commission_bps: commissionBps, referee_max: refereeMax }),
        ipHash,
        now,
        productId
      ),
    ]);
  } catch (err) {
    const msg = String(err?.message || '');
    if (msg.includes('CHECK')) throw new HttpError(400, 'invalid_product');
    throw err;
  }

  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(409, 'product_limit_reached');
  }

  return json(
    {
      product: {
        id: productId,
        business_id: biz.id,
        name,
        price_ugx: price,
        commission_bps: commissionBps,
        referee_max: refereeMax,
        delivery_days: deliveryDays,
        status: 'active',
        visible_publicly: biz.approval_status === 'approved',
      },
    },
    201,
    cors
  );
}

async function handlePatchProduct(request, env, productId, now, cors) {
  assertEnv(env, ['DB', 'HASH_SALT', 'FIREBASE_PROJECT_ID']);
  const user = await requireSeller(request, env, now);
  const product = await loadProductOwned(env, productId, user.id);
  if (!product) throw new HttpError(404, 'product_not_found');
  const body = await readJson(request);

  const fields = {};
  if ('name' in body) fields.name = assertString(body.name, { min: 2, max: 120, code: 'invalid_name' });
  if ('description' in body) fields.description = assertString(body.description, { max: 2000, code: 'invalid_description' });
  if ('price_ugx' in body) {
    const p = assertInt(body.price_ugx, { min: 1, max: ABSOLUTE_MAX_PRICE_UGX, code: 'invalid_price' });
    if (p > BASIC_MAX_PRICE_UGX) throw new HttpError(400, 'price_above_limit');
    fields.price_ugx = p;
  }
  if ('category_id' in body) {
    const cid = assertId(body.category_id, 'invalid_category');
    const cat = await env.DB.prepare('SELECT id FROM categories WHERE id = ? LIMIT 1').bind(cid).first();
    if (!cat) throw new HttpError(400, 'invalid_category');
    fields.category_id = cid;
  }
  if ('commission_bps' in body) {
    fields.commission_bps = assertInt(body.commission_bps, {
      min: MIN_COMMISSION_BPS, max: 4800, code: 'invalid_commission_bps',
    });
  }
  if ('referee_max' in body) {
    const rm = assertInt(body.referee_max, { min: 1, max: 50, code: 'invalid_referee_max' });
    const used = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM product_referee_slots WHERE product_id = ? AND status IN ('pending','active')`
    ).bind(product.id).first();
    if (rm < Number(used?.n || 0)) throw new HttpError(409, 'referee_max_below_used_slots', { used: Number(used?.n || 0) });
    fields.referee_max = rm;
  }
  if ('delivery_text' in body) fields.delivery_text = assertString(body.delivery_text, { max: 300, code: 'invalid_delivery_text' });
  if ('delivery_days' in body) {
    fields.delivery_days = assertInt(body.delivery_days, { min: 1, max: BASIC_MAX_DELIVERY_DAYS, code: 'invalid_delivery_days' });
  }
  if ('image_ids' in body) fields.image_ids = JSON.stringify(validateImageIds(body.image_ids));

  // cap check on commission change
  if (fields.commission_bps != null) {
    const settings = await loadPlatformSettings(env);
    const total = fields.commission_bps + Number(product.referrer_bps) + settings.earnity_bps + settings.seller_reserve_bps;
    if (total > settings.deposit_cap_bps) {
      throw new HttpError(400, 'deposit_cap_exceeded', {
        max_commission_bps: settings.deposit_cap_bps - Number(product.referrer_bps) - settings.earnity_bps - settings.seller_reserve_bps,
      });
    }
  }

  const keys = Object.keys(fields);
  if (keys.length === 0) {
    return json({ product: { id: product.id, updated: false } }, 200, cors);
  }

  // Build guarded UPDATE with only allowed fields.
  const setParts = [];
  const binds = [];
  for (const k of keys) {
    if (k === 'image_ids') { setParts.push(`${k} = ?`); binds.push(fields[k]); }
    else { setParts.push(`${k} = ?`); binds.push(fields[k]); }
  }
  setParts.push('updated_at = ?');
  binds.push(now);
  binds.push(product.id, user.id);

  const ipHash = await hmacHex(env, 'ip:' + (request.headers.get('CF-Connecting-IP') || ''));

  const auditAction =
    fields.commission_bps != null && fields.commission_bps !== Number(product.commission_bps)
      ? 'product_commission_changed'
      : fields.referee_max != null && fields.referee_max !== Number(product.referee_max)
      ? 'referee_max_changed'
      : 'product_updated';

  const auditMeta = { keys };
  if (auditAction === 'product_commission_changed') {
    auditMeta.old_bps = Number(product.commission_bps);
    auditMeta.new_bps = fields.commission_bps;
  }
  if (auditAction === 'referee_max_changed') {
    auditMeta.old = Number(product.referee_max);
    auditMeta.new = fields.referee_max;
  }

  let results;
  try {
    results = await env.DB.batch([
      env.DB.prepare(
        `UPDATE products SET ${setParts.join(', ')}
         WHERE id = ? AND business_id IN (SELECT id FROM businesses WHERE owner_user_id = ?)`
      ).bind(...binds),
      env.DB.prepare(
        `INSERT INTO audit_log
           (id, actor_user_id, action, target_type, target_id, metadata, ip_hash, created_at)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?
         WHERE EXISTS (SELECT 1 FROM products WHERE id = ?)`
      ).bind(
        generateId('aud_'), user.id, auditAction, 'product', product.id,
        JSON.stringify(auditMeta), ipHash, now, product.id
      ),
    ]);
  } catch (err) {
    const msg = String(err?.message || '');
    if (msg.includes('CHECK')) throw new HttpError(400, 'invalid_product');
    throw err;
  }

  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    throw new HttpError(404, 'product_not_found');
  }

  const updated = await loadProductOwned(env, product.id, user.id);
  return json(
    {
      product: {
        id: updated.id,
        name: updated.name,
        description: updated.description,
        price_ugx: Number(updated.price_ugx),
        offer_price_ugx: updated.offer_price_ugx != null ? Number(updated.offer_price_ugx) : null,
        offer_starts_at: updated.offer_starts_at,
        offer_ends_at: updated.offer_ends_at,
        category_id: updated.category_id,
        image_ids: JSON.parse(updated.image_ids || '[]'),
        commission_bps: Number(updated.commission_bps),
        referee_max: Number(updated.referee_max),
        delivery_text: updated.delivery_text,
        delivery_days: Number(updated.delivery_days),
        status: updated.status,
        updated_at: Number(updated.updated_at),
      },
    },
    200,
    cors
  );
}

async function handleSetOffer(request, env, productId, now, cors) {
  assertEnv(env, ['DB', 'HASH_SALT', 'FIREBASE_PROJECT_ID']);
  const user = await requireSeller(request, env, now);
  const product = await loadProductOwned(env, productId, user.id);
  if (!product) throw new HttpError(404, 'product_not_found');
  const body = await readJson(request);

  const ipHash = await hmacHex(env, 'ip:' + (request.headers.get('CF-Connecting-IP') || ''));

  // Clear offer if requested.
  if (body.clear === true) {
    const results = await env.DB.batch([
      env.DB.prepare(
        `UPDATE products SET offer_price_ugx = NULL, offer_starts_at = NULL, offer_ends_at = NULL, updated_at = ?
         WHERE id = ? AND business_id IN (SELECT id FROM businesses WHERE owner_user_id = ?)`
      ).bind(now, product.id, user.id),
      env.DB.prepare(
        `INSERT INTO audit_log
           (id, actor_user_id, action, target_type, target_id, metadata, ip_hash, created_at)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?
         WHERE EXISTS (SELECT 1 FROM products WHERE id = ?)`
      ).bind(
        generateId('aud_'), user.id, 'offer_cleared', 'product', product.id,
        JSON.stringify({ previous_offer_price_ugx: product.offer_price_ugx }),
        ipHash, now, product.id
      ),
    ]);
    if ((results[0]?.meta?.changes ?? 0) !== 1) throw new HttpError(404, 'product_not_found');
    return json({ product_id: product.id, offer: null }, 200, cors);
  }

  const offerPrice = assertInt(body.offer_price_ugx, { min: 1, max: ABSOLUTE_MAX_PRICE_UGX, code: 'invalid_offer_price' });
  if (offerPrice >= Number(product.price_ugx)) throw new HttpError(400, 'offer_price_not_lower');
  const startsAt = assertInt(body.offer_starts_at, { min: 0, max: 4102444800, code: 'invalid_offer_start' });
  const endsAt = assertInt(body.offer_ends_at, { min: 0, max: 4102444800, code: 'invalid_offer_end' });
  if (endsAt <= startsAt) throw new HttpError(400, 'invalid_offer_range');
  if (endsAt - startsAt > OFFER_MAX_SPAN_SECONDS) throw new HttpError(400, 'offer_too_long');

  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE products SET offer_price_ugx = ?, offer_starts_at = ?, offer_ends_at = ?, updated_at = ?
       WHERE id = ? AND business_id IN (SELECT id FROM businesses WHERE owner_user_id = ?)`
    ).bind(offerPrice, startsAt, endsAt, now, product.id, user.id),
    env.DB.prepare(
      `INSERT INTO audit_log
         (id, actor_user_id, action, target_type, target_id, metadata, ip_hash, created_at)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?
       WHERE EXISTS (SELECT 1 FROM products WHERE id = ?)`
    ).bind(
      generateId('aud_'), user.id, 'offer_set', 'product', product.id,
      JSON.stringify({ offer_price_ugx: offerPrice, starts_at: startsAt, ends_at: endsAt }),
      ipHash, now, product.id
    ),
  ]);
  if ((results[0]?.meta?.changes ?? 0) !== 1) throw new HttpError(404, 'product_not_found');

  return json(
    { product_id: product.id, offer: { offer_price_ugx: offerPrice, starts_at: startsAt, ends_at: endsAt } },
    200,
    cors
  );
}

async function handleSetStatus(request, env, productId, now, cors) {
  assertEnv(env, ['DB', 'HASH_SALT', 'FIREBASE_PROJECT_ID']);
  const user = await requireSeller(request, env, now);
  const product = await loadProductOwned(env, productId, user.id);
  if (!product) throw new HttpError(404, 'product_not_found');
  const body = await readJson(request);
  const status = body.status;
  if (status !== 'active' && status !== 'hidden') throw new HttpError(400, 'invalid_status');

  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE products SET status = ?, updated_at = ?
       WHERE id = ? AND business_id IN (SELECT id FROM businesses WHERE owner_user_id = ?)`
    ).bind(status, now, product.id, user.id),
    env.DB.prepare(
      `INSERT INTO audit_log
         (id, actor_user_id, action, target_type, target_id, metadata, ip_hash, created_at)
       SELECT ?, ?, ?, ?, ?, ?, ?, ?
       WHERE EXISTS (SELECT 1 FROM products WHERE id = ?)`
    ).bind(
      generateId('aud_'), user.id, 'product_updated', 'product', product.id,
      JSON.stringify({ status }), await hmacHex(env, 'ip:' + (request.headers.get('CF-Connecting-IP') || '')),
      now, product.id
    ),
  ]);
  if ((results[0]?.meta?.changes ?? 0) !== 1) throw new HttpError(404, 'product_not_found');
  return json({ product_id: product.id, status }, 200, cors);
}

async function handleMyProducts(request, env, now, cors) {
  assertEnv(env, ['DB', 'FIREBASE_PROJECT_ID']);
  const user = await requireSeller(request, env, now);
  const biz = await loadOwnedBusiness(env, user.id);
  if (!biz) throw new HttpError(404, 'business_not_found');

  const rows = await env.DB.prepare(
    `SELECT id, name, price_ugx, offer_price_ugx, offer_starts_at, offer_ends_at,
            category_id, commission_bps, referee_max, delivery_days, status,
            created_at, updated_at
     FROM products WHERE business_id = ? ORDER BY created_at DESC`
  ).bind(biz.id).all();

  return json(
    {
      products: (rows.results || []).map((p) => ({
        id: p.id,
        name: p.name,
        price_ugx: Number(p.price_ugx),
        offer_price_ugx: p.offer_price_ugx != null ? Number(p.offer_price_ugx) : null,
        offer_starts_at: p.offer_starts_at,
        offer_ends_at: p.offer_ends_at,
        category_id: p.category_id,
        commission_bps: Number(p.commission_bps),
        referee_max: Number(p.referee_max),
        delivery_days: Number(p.delivery_days),
        status: p.status,
        created_at: Number(p.created_at),
        updated_at: Number(p.updated_at),
      })),
    },
    200,
    cors
  );
}

async function handleProductSlots(request, env, productId, now, cors) {
  assertEnv(env, ['DB', 'FIREBASE_PROJECT_ID']);
  const user = await requireSeller(request, env, now);
  const product = await loadProductOwned(env, productId, user.id);
  if (!product) throw new HttpError(404, 'product_not_found');

  const rows = await env.DB.prepare(
    `SELECT s.id, s.status, s.claimed_at, s.activated_at, s.released_at, s.expires_at,
            u.id AS referee_user_id, ru.username AS referee_username
     FROM product_referee_slots s
     JOIN users u ON u.id = s.referee_user_id
     LEFT JOIN referee_usernames ru ON ru.user_id = u.id
     WHERE s.product_id = ?
     ORDER BY s.claimed_at DESC`
  ).bind(product.id).all();

  return json(
    {
      product_id: product.id,
      slots: (rows.results || []).map((r) => ({
        id: r.id,
        referee_username: r.referee_username || null,
        status: r.status,
        claimed_at: Number(r.claimed_at),
        activated_at: r.activated_at != null ? Number(r.activated_at) : null,
        released_at: r.released_at != null ? Number(r.released_at) : null,
        expires_at: r.expires_at != null ? Number(r.expires_at) : null,
      })),
    },
    200,
    cors
  );
}

/* ------------------------------------------------------------------ */
/* Referee handlers                                                   */
/* ------------------------------------------------------------------ */

async function handleClaimSlot(request, env, productId, now, cors) {
  assertEnv(env, ['DB', 'HASH_SALT', 'FIREBASE_PROJECT_ID']);
  const { user } = await requireAuth(request, env, now);
  requireAccountType(user, 'referee');
  assertId(productId, 'invalid_product_id');

  // Must have a username.
  const uname = await env.DB.prepare(
    'SELECT username FROM referee_usernames WHERE user_id = ? LIMIT 1'
  ).bind(user.id).first();
  if (!uname) throw new HttpError(403, 'referee_username_required');

  // Product must be active and belong to an approved business.
  const product = await env.DB.prepare(
    `SELECT p.id, p.business_id, p.referee_max, p.commission_bps, p.status,
            b.owner_user_id, b.approval_status
     FROM products p JOIN businesses b ON b.id = p.business_id
     WHERE p.id = ? LIMIT 1`
  ).bind(productId).first();
  if (!product) throw new HttpError(404, 'product_not_found');
  if (product.status !== 'active') throw new HttpError(404, 'product_not_found');
  if (product.approval_status !== 'approved') throw new HttpError(404, 'product_not_found');

  // Referee cannot be the owner.
  if (product.owner_user_id === user.id) throw new HttpError(400, 'own_product');

  const slotId = generateId('slot_');
  const ipHash = await hmacHex(env, 'ip:' + (request.headers.get('CF-Connecting-IP') || ''));
  const expiresAt = now + SLOT_TTL_SECONDS;

  let results;
  try {
    results = await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO product_referee_slots
           (id, product_id, referee_user_id, status, claimed_at, expires_at)
         SELECT ?, ?, ?, 'pending', ?, ?
         WHERE (SELECT COUNT(*) FROM product_referee_slots
                WHERE product_id = ? AND status IN ('pending','active')) < ?
           AND NOT EXISTS (
             SELECT 1 FROM product_referee_slots
             WHERE product_id = ? AND referee_user_id = ? AND status IN ('pending','active')
           )`
      ).bind(
        slotId, product.id, user.id, now, expiresAt,
        product.id, Number(product.referee_max),
        product.id, user.id
      ),
      env.DB.prepare(
        `INSERT INTO audit_log
           (id, actor_user_id, action, target_type, target_id, metadata, ip_hash, created_at)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?
         WHERE EXISTS (SELECT 1 FROM product_referee_slots WHERE id = ?)`
      ).bind(
        generateId('aud_'), user.id, 'referee_slot_claimed', 'product', product.id,
        JSON.stringify({ slot_id: slotId }), ipHash, now, slotId
      ),
    ]);
  } catch (err) {
    const msg = String(err?.message || '');
    if (msg.includes('UNIQUE')) throw new HttpError(409, 'slot_already_claimed');
    throw err;
  }

  if ((results[0]?.meta?.changes ?? 0) !== 1) {
    // Could be full OR already holds a slot. Disambiguate for a clean error.
    const existing = await env.DB.prepare(
      `SELECT id FROM product_referee_slots
       WHERE product_id = ? AND referee_user_id = ? AND status IN ('pending','active') LIMIT 1`
    ).bind(product.id, user.id).first();
    if (existing) throw new HttpError(409, 'slot_already_claimed');
    throw new HttpError(409, 'slots_full');
  }

  return json(
    {
      slot: {
        id: slotId,
        product_id: product.id,
        status: 'pending',
        claimed_at: now,
        expires_at: expiresAt,
      },
      link_params: { product_id: product.id, referee_username: uname.username },
    },
    201,
    cors
  );
}

async function handleMySlots(request, env, now, cors) {
  assertEnv(env, ['DB', 'FIREBASE_PROJECT_ID']);
  const { user } = await requireAuth(request, env, now);
  requireAccountType(user, 'referee');

  const rows = await env.DB.prepare(
    `SELECT s.id, s.product_id, s.status, s.claimed_at, s.activated_at, s.released_at, s.expires_at,
            p.name AS product_name, p.price_ugx, p.offer_price_ugx, p.offer_starts_at, p.offer_ends_at,
            p.commission_bps
     FROM product_referee_slots s
     JOIN products p ON p.id = s.product_id
     WHERE s.referee_user_id = ?
     ORDER BY s.claimed_at DESC`
  ).bind(user.id).all();

  return json(
    {
      slots: (rows.results || []).map((r) => {
        const { price } = effectivePrice(r, now);
        return {
          id: r.id,
          product_id: r.product_id,
          product_name: r.product_name,
          effective_price_ugx: price,
          commission_bps: Number(r.commission_bps),
          status: r.status,
          claimed_at: Number(r.claimed_at),
          activated_at: r.activated_at != null ? Number(r.activated_at) : null,
          released_at: r.released_at != null ? Number(r.released_at) : null,
          expires_at: r.expires_at != null ? Number(r.expires_at) : null,
        };
      }),
    },
    200,
    cors
  );
}

/* ------------------------------------------------------------------ */
/* Internal handlers (service-to-service)                             */
/* ------------------------------------------------------------------ */

async function requireInternal(request, env) {
  if (request.headers.get('Origin')) throw new HttpError(403, 'forbidden');
  assertEnv(env, ['DB', 'INTERNAL_KEY']);
  const provided = request.headers.get('X-Internal-Key') || '';
  if (!timingSafeEqual(provided, env.INTERNAL_KEY)) {
    throw new HttpError(401, 'unauthorized');
  }
}

async function handleCheckoutQuote(request, env, now) {
  await requireInternal(request, env);
  const body = await readJson(request);
  const productId = assertId(body.product_id, 'invalid_product_id');
  let refereeUserId = null;
  if (body.referee_user_id != null) {
    refereeUserId = assertId(body.referee_user_id, 'invalid_referee_user_id');
  }

  const product = await env.DB.prepare(
    `SELECT p.*, b.referrer_user_id, b.referrer_bps, b.approval_status, b.owner_user_id
     FROM products p JOIN businesses b ON b.id = p.business_id
     WHERE p.id = ? LIMIT 1`
  ).bind(productId).first();
  if (!product) throw new HttpError(404, 'product_not_found');
  if (product.status !== 'active') throw new HttpError(404, 'product_not_found');
  if (product.approval_status !== 'approved') throw new HttpError(404, 'product_not_found');

  const settings = await loadPlatformSettings(env);
  const { price } = effectivePrice(product, now);

  let productRefereeBps = 0;
  let slotStatus = null;
  if (refereeUserId) {
    if (product.owner_user_id === refereeUserId) {
      throw new HttpError(400, 'own_product');
    }
    const slot = await env.DB.prepare(
      `SELECT id, status FROM product_referee_slots
       WHERE product_id = ? AND referee_user_id = ? AND status IN ('pending','active') LIMIT 1`
    ).bind(product.id, refereeUserId).first();
    if (slot) {
      slotStatus = slot.status;
      productRefereeBps = Number(product.commission_bps);
    }
  }

  const businessReferrerId = product.referrer_user_id || null;
  const businessReferrerBps = Number(product.referrer_bps || 0);

  const totalBps = productRefereeBps + businessReferrerBps + settings.earnity_bps + settings.seller_reserve_bps;
  if (totalBps > settings.deposit_cap_bps) {
    throw new HttpError(400, 'deposit_cap_exceeded');
  }

  const refereeShare = Math.floor((price * productRefereeBps) / 10000);
  const referrerShare = Math.floor((price * businessReferrerBps) / 10000);
  const reserveShare = Math.floor((price * settings.seller_reserve_bps) / 10000);
  const earnityShareRaw = Math.floor((price * settings.earnity_bps) / 10000);
  
  // Deposit is the floored total; leftover shillings go to Earnity.
  const totalDeposit = Math.floor((price * totalBps) / 10000);
  const earnityShare = totalDeposit - refereeShare - referrerShare - reserveShare;

  return json(
    {
      product_id: product.id,
      effective_price_ugx: price,
      product_referee_bps: productRefereeBps,
      business_referrer_user_id: businessReferrerId,
      business_referrer_bps: businessReferrerBps,
      earnity_bps: settings.earnity_bps,
      seller_reserve_bps: settings.seller_reserve_bps,
      shares: {
        product_referee_ugx: refereeShare,
        business_referrer_ugx: referrerShare,
        seller_reserve_ugx: reserveShare,
        earnity_ugx: earnityShare,
      },
      total_deposit_ugx: totalDeposit,
      slot_status: slotStatus,
    },
    200,
    {}
  );
}

async function handleSlotActivate(request, env, now) {
  await requireInternal(request, env);
  const body = await readJson(request);
  const productId = assertId(body.product_id, 'invalid_product_id');
  const refereeUserId = assertId(body.referee_user_id, 'invalid_referee_user_id');
  const paymentId = assertId(body.payment_id, 'invalid_payment_id');

  // Idempotent: only flip pending->active if payment_id not already recorded on an active slot for this pair.
  const results = await env.DB.batch([
    env.DB.prepare(
      `UPDATE product_referee_slots
       SET status = 'active', activated_at = ?, expires_at = NULL, payment_id = ?
       WHERE product_id = ? AND referee_user_id = ? AND status = 'pending'
         AND (payment_id IS NULL OR payment_id != ?)`
    ).bind(now, paymentId, productId, refereeUserId, paymentId),
    env.DB.prepare(
      `UPDATE product_referee_slots
       SET payment_id = ?
       WHERE product_id = ? AND referee_user_id = ? AND status = 'active' AND payment_id IS NULL`
    ).bind(paymentId, productId, refereeUserId),
  ]);

  const changed = results[0]?.meta?.changes ?? 0;

  return json(
    {
      activated: changed === 1,
      already_active: changed === 0,
      product_id: productId,
      referee_user_id: refereeUserId,
    },
    200,
    {}
  );
}

async function handleReleaseExpiredSlots(request, env, now) {
  await requireInternal(request, env);

  // Find expired pending slots first (read is fine; writes are guarded).
  const expired = await env.DB.prepare(
    `SELECT id, product_id, referee_user_id FROM product_referee_slots
     WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at <= ?
     LIMIT 500`
  ).bind(now).all();

  const slots = expired.results || [];
  if (slots.length === 0) return json({ released: 0 }, 200, {});

  const ipHash = await hmacHex(env, 'internal:release-expired');
  const batchStmts = [];
  for (const s of slots) {
    batchStmts.push(
      env.DB.prepare(
        `UPDATE product_referee_slots
         SET status = 'released', released_at = ?
         WHERE id = ? AND status = 'pending' AND expires_at <= ?`
      ).bind(now, s.id, now)
    );
    batchStmts.push(
      env.DB.prepare(
        `INSERT INTO audit_log
           (id, actor_user_id, action, target_type, target_id, metadata, ip_hash, created_at)
         SELECT ?, NULL, ?, ?, ?, ?, ?, ?
         WHERE EXISTS (SELECT 1 FROM product_referee_slots WHERE id = ? AND status = 'released' AND released_at = ?)`
      ).bind(
        generateId('aud_'),
        'referee_slot_released',
        'product',
        s.product_id,
        JSON.stringify({ slot_id: s.id, referee_user_id: s.referee_user_id }),
        ipHash,
        now,
        s.id,
        now
      )
    );
  }

  await env.DB.batch(batchStmts);

  const releasedCount = batchStmts
    .filter((_, i) => i % 2 === 0) // we can't read meta easily; recount instead
    .length;

  // Recount actual released to be safe.
  const recount = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM product_referee_slots
     WHERE status = 'released' AND released_at = ?`
  ).bind(now).first();

  return json({ released: Number(recount?.n || 0) || releasedCount }, 200, {});
}

/* ------------------------------------------------------------------ */
/* Worker entrypoint                                                  */
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

    // Internal paths: reject browser-originated requests with no CORS.
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
      /* -------- Public -------- */
      if (path === '/health' && request.method === 'GET') {
        return await handleHealth(env, now, cors);
      }
      if (path === '/categories' && request.method === 'GET') {
        return await handleCategories(env, cors);
      }
      const publicProductMatch = path.match(/^\/products\/([^/]+)$/);
      if (publicProductMatch && request.method === 'GET') {
        return await handlePublicProduct(env, publicProductMatch[1], now, cors);
      }
      const storeMatch = path.match(/^\/store\/([^/]+)$/);
      if (storeMatch && request.method === 'GET') {
        return await handlePublicStore(env, storeMatch[1], url, now, cors);
      }

      /* -------- Seller business -------- */
      if (path === '/business' && request.method === 'POST') {
        return await handleCreateBusiness(request, env, now, cors);
      }
      if (path === '/business/me' && request.method === 'GET') {
        return await handleGetMyBusiness(request, env, now, cors);
      }
      if (path === '/business/me' && request.method === 'PATCH') {
        return await handlePatchMyBusiness(request, env, now, cors);
      }
      if (path === '/business/me/referrer-rate' && request.method === 'POST') {
        return await handleRaiseReferrerRate(request, env, now, cors);
      }

      /* -------- Seller products -------- */
      if (path === '/products' && request.method === 'POST') {
        return await handleCreateProduct(request, env, now, cors);
      }
      if (path === '/business/me/products' && request.method === 'GET') {
        return await handleMyProducts(request, env, now, cors);
      }
      const patchProductMatch = path.match(/^\/products\/([^/]+)$/);
      if (patchProductMatch && request.method === 'PATCH') {
        return await handlePatchProduct(request, env, patchProductMatch[1], now, cors);
      }
      const offerMatch = path.match(/^\/products\/([^/]+)\/offer$/);
      if (offerMatch && request.method === 'POST') {
        return await handleSetOffer(request, env, offerMatch[1], now, cors);
      }
      const statusMatch = path.match(/^\/products\/([^/]+)\/status$/);
      if (statusMatch && request.method === 'POST') {
        return await handleSetStatus(request, env, statusMatch[1], now, cors);
      }
      const slotsMatch = path.match(/^\/products\/([^/]+)\/slots$/);
      if (slotsMatch && request.method === 'GET') {
        return await handleProductSlots(request, env, slotsMatch[1], now, cors);
      }

      /* -------- Referee -------- */
      const claimMatch = path.match(/^\/products\/([^/]+)\/referee-slot$/);
      if (claimMatch && request.method === 'POST') {
        return await handleClaimSlot(request, env, claimMatch[1], now, cors);
      }
      if (path === '/referee/slots' && request.method === 'GET') {
        return await handleMySlots(request, env, now, cors);
      }

      /* -------- Internal -------- */
      if (path === '/internal/checkout-quote' && request.method === 'POST') {
        return await handleCheckoutQuote(request, env, now);
      }
      if (path === '/internal/slot-activate' && request.method === 'POST') {
        return await handleSlotActivate(request, env, now);
      }
      if (path === '/internal/release-expired-slots' && request.method === 'POST') {
        return await handleReleaseExpiredSlots(request, env, now);
      }

      // 405 for known paths with wrong method
      const knownPaths = [
        '/health','/categories','/business','/business/me','/business/me/referrer-rate',
        '/products','/business/me/products','/referee/slots',
        '/internal/checkout-quote','/internal/slot-activate','/internal/release-expired-slots',
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
