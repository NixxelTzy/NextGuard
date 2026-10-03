/**
 * NextGuard - Preset Firewall Rules per Endpoint
 *
 * Kumpulan konfigurasi firewall yang sudah disesuaikan
 * untuk semua jenis endpoint umum yang ada di website.
 *
 * Cara pakai:
 *   import { ENDPOINT_PRESETS } from 'nextguard/presets';
 *   export const POST = withNextGuard(handler, ENDPOINT_PRESETS.LOGIN);
 */

import { NextGuardConfig } from './types.js';

// ─────────────────────────────────────────────────────────────────────────────
// TIER A — Endpoint Kritis (proteksi paling ketat)
// ─────────────────────────────────────────────────────────────────────────────

/** Login / Sign In endpoint */
const LOGIN: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: {
    windowMs: 60 * 1000,        // 1 menit
    max: 5,                      // Maksimal 5 percobaan login per menit
    jailThreshold: 10,           // Banned setelah 10 request
    jailDurationMs: 15 * 60 * 1000, // Banned 15 menit
  },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true, inspectQuery: true },
  xss:              { enabled: true, sensitivity: 'high' },
  commandInjection: { enabled: true },
  pathTraversal:    { enabled: true },
  badBots:          { enabled: true, blockEmptyUserAgent: true },
  payloadGuard:     { enabled: true, maxBodySize: 10 * 1024 },  // 10 KB saja untuk login
};

/** Register / Sign Up endpoint */
const REGISTER: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: {
    windowMs: 10 * 60 * 1000,   // 10 menit
    max: 3,                      // Hanya 3 pendaftaran per 10 menit per IP
    jailThreshold: 6,
    jailDurationMs: 30 * 60 * 1000, // Banned 30 menit
  },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true },
  xss:              { enabled: true },
  commandInjection: { enabled: true },
  badBots:          { enabled: true, blockEmptyUserAgent: true },
  payloadGuard:     { enabled: true, maxBodySize: 50 * 1024 }, // 50 KB
};

/** Forgot Password / Reset Password endpoint */
const FORGOT_PASSWORD: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: {
    windowMs: 5 * 60 * 1000,    // 5 menit
    max: 3,                      // Maksimal 3 request reset per 5 menit
    jailThreshold: 6,
    jailDurationMs: 30 * 60 * 1000,
  },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true, inspectQuery: true },
  xss:          { enabled: true },
  badBots:      { enabled: true, blockEmptyUserAgent: true },
};

/** Logout endpoint */
const LOGOUT: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 20 },
  badBots: { enabled: true },
};

/** Verify OTP / 2FA endpoint */
const VERIFY_OTP: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: {
    windowMs: 5 * 60 * 1000,
    max: 5,                       // 5 percobaan OTP per 5 menit
    jailThreshold: 10,
    jailDurationMs: 30 * 60 * 1000,
  },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true },
  xss: { enabled: true },
};

// ─────────────────────────────────────────────────────────────────────────────
// TIER B — Endpoint Pengguna (proteksi standar kuat)
// ─────────────────────────────────────────────────────────────────────────────

/** Profile — tampilkan / update profil pengguna */
const PROFILE: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 30 },
  sqlInjection: { enabled: true, sensitivity: 'medium', inspectBody: true, inspectQuery: true },
  xss:              { enabled: true },
  commandInjection: { enabled: true },
  pathTraversal:    { enabled: true },
  badBots:          { enabled: true },
  payloadGuard:     { enabled: true, maxBodySize: 5 * 1024 * 1024 }, // 5 MB
};

/** Change Password endpoint */
const CHANGE_PASSWORD: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: {
    windowMs: 60 * 1000,
    max: 5,
    jailDurationMs: 15 * 60 * 1000,
  },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true },
  xss: { enabled: true },
  badBots: { enabled: true, blockEmptyUserAgent: true },
};

/** File Upload — avatar, dokumen, gambar */
const FILE_UPLOAD: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 20 },
  sqlInjection: { enabled: true, inspectBody: false }, // body adalah binary, skip body check
  xss:          { enabled: false }, // binary payload, skip
  pathTraversal:{ enabled: true, inspectQuery: true },
  badBots:      { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 50 * 1024 * 1024 }, // 50 MB
};

/** Comment / Review endpoint */
const COMMENT: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 10 },
  sqlInjection: { enabled: true, sensitivity: 'medium', inspectBody: true },
  xss:              { enabled: true, sensitivity: 'high' }, // XSS tinggi krn konten bisa di-render
  commandInjection: { enabled: true },
  badBots:          { enabled: true },
  payloadGuard:     { enabled: true, maxBodySize: 10 * 1024 }, // 10 KB per comment
};

/** Messaging / Chat endpoint */
const MESSAGE: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 60 }, // 60 pesan per menit
  sqlInjection: { enabled: true, inspectBody: true },
  xss:          { enabled: true, sensitivity: 'high' },
  badBots:      { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 1 * 1024 * 1024 }, // 1 MB
};

// ─────────────────────────────────────────────────────────────────────────────
// TIER C — Endpoint Data & API (proteksi query-focused)
// ─────────────────────────────────────────────────────────────────────────────

/** Search endpoint — query pengguna */
const SEARCH: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 100 },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectQuery: true, inspectBody: false },
  xss:              { enabled: true, inspectQuery: true },
  commandInjection: { enabled: true },
  pathTraversal:    { enabled: true, inspectQuery: true },
  badBots:          { enabled: true, knownScanners: true },
};

/** Products / Items listing endpoint */
const PRODUCTS: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 200 },
  sqlInjection: { enabled: true, sensitivity: 'medium', inspectQuery: true },
  xss:          { enabled: true, inspectQuery: true },
  badBots:      { enabled: true, knownScanners: true },
};

/** Single item / detail endpoint (e.g. /api/products/:id) */
const PRODUCT_DETAIL: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 300 },
  sqlInjection: { enabled: true, sensitivity: 'medium', inspectQuery: true },
  xss:          { enabled: false },
  pathTraversal:{ enabled: true },
  badBots:      { enabled: true, knownScanners: true },
};

/** Create / Update data (POST/PUT forms) */
const CREATE_UPDATE: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 30 },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true, inspectQuery: true },
  xss:              { enabled: true, sensitivity: 'high' },
  commandInjection: { enabled: true },
  pathTraversal:    { enabled: true },
  badBots:          { enabled: true },
  payloadGuard:     { enabled: true, maxBodySize: 5 * 1024 * 1024 }, // 5 MB
};

/** Delete data endpoint */
const DELETE_DATA: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 20 },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectQuery: true, inspectBody: true },
  xss:          { enabled: false }, // delete requests biasanya tidak ada rich content
  badBots:      { enabled: true },
};

/** Bulk operations (batch create/update/delete) */
const BULK: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: {
    windowMs: 60 * 1000,
    max: 10,                     // Bulk ops sangat dibatasi
    jailThreshold: 20,
    jailDurationMs: 10 * 60 * 1000,
  },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true },
  xss:          { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 10 * 1024 * 1024 }, // 10 MB untuk batch
};

// ─────────────────────────────────────────────────────────────────────────────
// TIER D — Endpoint Transaksi & Keuangan (proteksi ultra ketat)
// ─────────────────────────────────────────────────────────────────────────────

/** Payment / Checkout endpoint */
const PAYMENT: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: {
    windowMs: 60 * 1000,
    max: 5,                      // Hanya 5 transaksi per menit
    jailThreshold: 8,
    jailDurationMs: 30 * 60 * 1000,
  },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true, inspectQuery: true },
  xss:              { enabled: true, sensitivity: 'high' },
  commandInjection: { enabled: true },
  pathTraversal:    { enabled: true },
  badBots:          { enabled: true, blockEmptyUserAgent: true, knownScanners: true },
  payloadGuard:     { enabled: true, maxBodySize: 50 * 1024 }, // 50 KB
};

/** Payment Webhook (dari payment gateway, e.g. Stripe, Midtrans) */
const PAYMENT_WEBHOOK: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 100 }, // Webhook bisa banyak
  sqlInjection: { enabled: false }, // payload dari gateway terpercaya
  xss:          { enabled: false },
  ipFilter: {
    // Whitelist IP gateway pembayaran (contoh Midtrans & Stripe)
    whitelist: [
      '202.152.0.0/16',   // Midtrans Indonesia
      '3.18.0.0/16',      // Stripe AWS US-East
      '54.187.0.0/16',    // Stripe AWS US-West
    ],
    trustProxy: true,
  },
  payloadGuard: { enabled: true, maxBodySize: 1 * 1024 * 1024 },
};

/** Withdraw / Transfer funds endpoint */
const WITHDRAW: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: {
    windowMs: 60 * 1000,
    max: 3,
    jailThreshold: 5,
    jailDurationMs: 60 * 60 * 1000, // Banned 1 jam jika mencurigakan
  },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true },
  xss:              { enabled: true },
  commandInjection: { enabled: true },
  badBots:          { enabled: true, blockEmptyUserAgent: true },
  payloadGuard:     { enabled: true, maxBodySize: 10 * 1024 },
};

// ─────────────────────────────────────────────────────────────────────────────
// TIER E — Endpoint Admin & Internal (IP whitelist wajib)
// ─────────────────────────────────────────────────────────────────────────────

/** Admin panel endpoint */
const ADMIN: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 30 },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true, inspectQuery: true },
  xss:              { enabled: true, sensitivity: 'high' },
  commandInjection: { enabled: true },
  pathTraversal:    { enabled: true },
  badBots:          { enabled: true, blockEmptyUserAgent: true, knownScanners: true },
  // Tambahkan ipFilter.whitelist dengan IP server/office kamu
  ipFilter: {
    whitelist: ['127.0.0.1', '::1'],  // Ganti dengan IP kantor/server kamu
    trustProxy: true,
  },
};

/** Admin Login endpoint */
const ADMIN_LOGIN: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: {
    windowMs: 5 * 60 * 1000,    // 5 menit
    max: 3,                      // Hanya 3 percobaan login admin per 5 menit
    jailThreshold: 5,
    jailDurationMs: 60 * 60 * 1000, // Banned 1 jam
  },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true },
  xss:              { enabled: true },
  commandInjection: { enabled: true },
  badBots:          { enabled: true, blockEmptyUserAgent: true, knownScanners: true },
  ipFilter: {
    whitelist: ['127.0.0.1', '::1'],
    trustProxy: true,
  },
};

/** Internal API / Microservice endpoint */
const INTERNAL_API: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 500 }, // Tinggi untuk internal calls
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true },
  xss:          { enabled: true },
  pathTraversal:{ enabled: true },
  ipFilter: {
    whitelist: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.1'],
  },
};

/** Webhook receiver umum (dari external service) */
const WEBHOOK: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 200 },
  sqlInjection: { enabled: true, sensitivity: 'medium', inspectBody: true },
  xss:          { enabled: false },
  commandInjection: { enabled: true },
  pathTraversal:    { enabled: false },
  payloadGuard: { enabled: true, maxBodySize: 5 * 1024 * 1024 },
};

// ─────────────────────────────────────────────────────────────────────────────
// TIER F — Endpoint Publik & CDN (proteksi ringan, throughput tinggi)
// ─────────────────────────────────────────────────────────────────────────────

/** Public API (tidak butuh auth, rate limit cukup) */
const PUBLIC_API: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 300 },
  sqlInjection: { enabled: true, sensitivity: 'low', inspectQuery: true },
  xss:          { enabled: true, sensitivity: 'low', inspectQuery: true },
  badBots:      { enabled: true, knownScanners: true },
};

/** Health check / Status endpoint */
const HEALTH_CHECK: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 600 }, // Monitoring tool sering poll
  sqlInjection: { enabled: false },
  xss:          { enabled: false },
  badBots:      { enabled: false },
};

/** Sitemap / Robots.txt / SEO endpoints */
const SEO: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 60 },
  sqlInjection: { enabled: false },
  xss:          { enabled: false },
  badBots:      { enabled: false }, // Search engine bots harus diizinkan
};

/** Newsletter subscribe / Unsubscribe */
const NEWSLETTER: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: {
    windowMs: 60 * 1000,
    max: 5,
    jailDurationMs: 10 * 60 * 1000,
  },
  sqlInjection: { enabled: true, sensitivity: 'medium', inspectBody: true },
  xss:          { enabled: true },
  badBots:      { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 1 * 1024 }, // 1 KB
};

/** Contact Form / Support Ticket endpoint */
const CONTACT_FORM: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: {
    windowMs: 60 * 1000,
    max: 3,                      // Anti-spam: 3 pesan per menit
    jailThreshold: 6,
    jailDurationMs: 10 * 60 * 1000,
  },
  sqlInjection: { enabled: true, sensitivity: 'medium', inspectBody: true },
  xss:              { enabled: true, sensitivity: 'high' },
  commandInjection: { enabled: true },
  badBots:          { enabled: true, blockEmptyUserAgent: true },
  payloadGuard:     { enabled: true, maxBodySize: 100 * 1024 }, // 100 KB
};

// ─────────────────────────────────────────────────────────────────────────────
// TIER G — Endpoint E-Commerce
// ─────────────────────────────────────────────────────────────────────────────

/** Cart (tambah/hapus item keranjang) */
const CART: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 60 },
  sqlInjection: { enabled: true, inspectBody: true, inspectQuery: true },
  xss:          { enabled: true },
  badBots:      { enabled: true, knownScanners: true },
  payloadGuard: { enabled: true, maxBodySize: 100 * 1024 },
};

/** Order history / Order detail */
const ORDER: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 50 },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectQuery: true },
  xss:          { enabled: false },
  pathTraversal:{ enabled: true },
  badBots:      { enabled: true, knownScanners: true },
};

/** Coupon / Promo code endpoint (anti brute-force kode promo) */
const COUPON: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: {
    windowMs: 60 * 1000,
    max: 10,
    jailThreshold: 20,
    jailDurationMs: 10 * 60 * 1000,
  },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true, inspectQuery: true },
  xss:          { enabled: true },
  badBots:      { enabled: true },
};

/** Rating / Review produk */
const RATING: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 10 },
  sqlInjection: { enabled: true, inspectBody: true },
  xss:          { enabled: true, sensitivity: 'high' },
  badBots:      { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 5 * 1024 }, // 5 KB per review
};

// ─────────────────────────────────────────────────────────────────────────────
// TIER H — Endpoint Media & Konten
// ─────────────────────────────────────────────────────────────────────────────

/** Image / Media upload */
const MEDIA_UPLOAD: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 10 },
  sqlInjection: { enabled: false }, // payload binary
  xss:          { enabled: false },
  pathTraversal:{ enabled: true, inspectQuery: true },
  badBots:      { enabled: true },
  payloadGuard: { enabled: true, maxBodySize: 100 * 1024 * 1024 }, // 100 MB
};

/** Blog post / Article CRUD */
const BLOG: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 20 },
  sqlInjection: { enabled: true, inspectBody: true, inspectQuery: true },
  xss:          { enabled: true, sensitivity: 'high' }, // Konten HTML bisa dirender
  commandInjection: { enabled: true },
  badBots:          { enabled: true, knownScanners: true },
  payloadGuard:     { enabled: true, maxBodySize: 10 * 1024 * 1024 }, // 10 MB
};

// ─────────────────────────────────────────────────────────────────────────────
// TIER I — Endpoint Auth Lanjutan
// ─────────────────────────────────────────────────────────────────────────────

/** OAuth / SSO callback endpoint */
const OAUTH_CALLBACK: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 30 },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectQuery: true },
  xss:          { enabled: true, inspectQuery: true },
  pathTraversal:{ enabled: true, inspectQuery: true },
  badBots:      { enabled: true },
};

/** Token refresh endpoint */
const TOKEN_REFRESH: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: {
    windowMs: 60 * 1000,
    max: 10,
    jailThreshold: 20,
    jailDurationMs: 5 * 60 * 1000,
  },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true },
  xss:          { enabled: false },
  badBots:      { enabled: true, blockEmptyUserAgent: true },
  payloadGuard: { enabled: true, maxBodySize: 4 * 1024 }, // 4 KB
};

/** API Key management endpoint */
const API_KEY: NextGuardConfig = {
  mode: 'enforce',
  rateLimit: { windowMs: 60 * 1000, max: 20 },
  sqlInjection: { enabled: true, sensitivity: 'high', inspectBody: true },
  xss:          { enabled: true },
  commandInjection: { enabled: true },
  badBots:          { enabled: true, blockEmptyUserAgent: true },
};

// ─────────────────────────────────────────────────────────────────────────────
// Export semua preset
// ─────────────────────────────────────────────────────────────────────────────

export const ENDPOINT_PRESETS = {
  // Autentikasi
  LOGIN,
  REGISTER,
  LOGOUT,
  FORGOT_PASSWORD,
  CHANGE_PASSWORD,
  VERIFY_OTP,
  OAUTH_CALLBACK,
  TOKEN_REFRESH,
  API_KEY,

  // Pengguna
  PROFILE,
  FILE_UPLOAD,
  COMMENT,
  MESSAGE,

  // Data & API
  SEARCH,
  PRODUCTS,
  PRODUCT_DETAIL,
  CREATE_UPDATE,
  DELETE_DATA,
  BULK,

  // Keuangan
  PAYMENT,
  PAYMENT_WEBHOOK,
  WITHDRAW,

  // Admin & Internal
  ADMIN,
  ADMIN_LOGIN,
  INTERNAL_API,
  WEBHOOK,

  // E-Commerce
  CART,
  ORDER,
  COUPON,
  RATING,

  // Media & Konten
  MEDIA_UPLOAD,
  BLOG,

  // Publik
  PUBLIC_API,
  HEALTH_CHECK,
  SEO,
  NEWSLETTER,
  CONTACT_FORM,
} as const;

export type EndpointPresetKey = keyof typeof ENDPOINT_PRESETS;
