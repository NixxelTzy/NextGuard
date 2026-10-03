/**
 * NextGuard - Contoh Semua Endpoint Express.js
 *
 * Setiap route sudah dilindungi dengan preset firewall
 * yang sesuai menggunakan ENDPOINT_PRESETS.
 *
 * Install:
 *   npm install express nextguard
 *   npm install -D @types/express
 */

import express from 'express';
import { nextGuardExpress, ENDPOINT_PRESETS, MemoryStore } from 'nextguard';

const app = express();
app.use(express.json({ limit: '100mb' })); // batas upload besar, guardian yg batasi
app.use(express.urlencoded({ extended: true }));

// ─────────────────────────────────────────────────────────────────────────────
// Helper: buat middleware firewall dari preset
// ─────────────────────────────────────────────────────────────────────────────
const fw = (preset: keyof typeof ENDPOINT_PRESETS) =>
  nextGuardExpress(ENDPOINT_PRESETS[preset]);

// ─────────────────────────────────────────────────────────────────────────────
// GLOBAL MIDDLEWARE
// Proteksi dasar yang berlaku untuk SEMUA route
// ─────────────────────────────────────────────────────────────────────────────
app.use(nextGuardExpress({
  mode: 'enforce',
  rateLimit: {
    windowMs: 60 * 1000,
    max: 200,
    jailThreshold: 400,
    jailDurationMs: 5 * 60 * 1000,
    store: new MemoryStore(),
  },
  badBots: { enabled: true, knownScanners: true },
  securityHeaders: { enabled: true },
  ipFilter: {
    blacklist: [],           // tambahkan IP buruk di sini
    trustProxy: true,
  },
  excludePaths: ['/health', '/favicon.ico'],
  onBlocked: (verdict) => {
    console.error(
      `[WAF] ${new Date().toISOString()} | ${verdict.threatType?.toUpperCase()} | ` +
      `IP: ${verdict.clientIp} | Reason: ${verdict.reason} | ReqID: ${verdict.requestId}`
    );
  },
}));

// ─────────────────────────────────────────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────────────────────────────────────────
const authRouter = express.Router();

authRouter.post('/login',           fw('LOGIN'),           (req, res) => {
  res.json({ token: 'jwt-token' });
});

authRouter.post('/register',        fw('REGISTER'),        (req, res) => {
  res.json({ user: { id: 1, ...req.body } });
});

authRouter.post('/logout',          fw('LOGOUT'),          (req, res) => {
  res.json({ success: true });
});

authRouter.post('/forgot-password', fw('FORGOT_PASSWORD'), (req, res) => {
  res.json({ message: 'Email reset terkirim' });
});

authRouter.post('/change-password', fw('CHANGE_PASSWORD'), (req, res) => {
  res.json({ success: true });
});

authRouter.post('/verify-otp',      fw('VERIFY_OTP'),      (req, res) => {
  res.json({ verified: true });
});

authRouter.post('/refresh-token',   fw('TOKEN_REFRESH'),   (req, res) => {
  res.json({ token: 'new-token' });
});

authRouter.get('/oauth/callback',   fw('OAUTH_CALLBACK'),  (req, res) => {
  res.json({ user: {} });
});

app.use('/api/auth', authRouter);

// ─────────────────────────────────────────────────────────────────────────────
// USER / PROFILE ROUTES
// ─────────────────────────────────────────────────────────────────────────────
const userRouter = express.Router();

userRouter.get ('/profile',         fw('PROFILE'),         (req, res) => {
  res.json({ user: { id: 1, name: 'John Doe' } });
});

userRouter.put ('/profile',         fw('PROFILE'),         (req, res) => {
  res.json({ user: req.body });
});

userRouter.post('/avatar',          fw('FILE_UPLOAD'),     (req, res) => {
  res.json({ url: 'https://cdn.example.com/avatar.jpg' });
});

userRouter.post('/change-password', fw('CHANGE_PASSWORD'), (req, res) => {
  res.json({ success: true });
});

userRouter.get ('/api-keys',        fw('API_KEY'),         (req, res) => {
  res.json({ keys: [] });
});

userRouter.post('/api-keys',        fw('API_KEY'),         (req, res) => {
  res.json({ key: 'sk-xxx' });
});

userRouter.delete('/api-keys/:id',  fw('API_KEY'),         (req, res) => {
  res.json({ deleted: true });
});

app.use('/api/user', userRouter);

// ─────────────────────────────────────────────────────────────────────────────
// PRODUCT & CATALOG ROUTES
// ─────────────────────────────────────────────────────────────────────────────
const productRouter = express.Router();

productRouter.get  ('/',            fw('PRODUCTS'),        (req, res) => {
  res.json({ products: [], page: req.query.page || 1 });
});

productRouter.post ('/',            fw('CREATE_UPDATE'),   (req, res) => {
  res.json({ product: { id: 1, ...req.body } });
});

productRouter.get  ('/:id',         fw('PRODUCT_DETAIL'),  (req, res) => {
  res.json({ product: { id: req.params.id } });
});

productRouter.put  ('/:id',         fw('CREATE_UPDATE'),   (req, res) => {
  res.json({ product: req.body });
});

productRouter.delete('/:id',        fw('DELETE_DATA'),     (req, res) => {
  res.json({ deleted: true });
});

productRouter.post ('/bulk',        fw('BULK'),            (req, res) => {
  res.json({ updated: (req.body.products || []).length });
});

app.use('/api/products', productRouter);

// ─────────────────────────────────────────────────────────────────────────────
// SEARCH ROUTE
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/search', fw('SEARCH'), (req, res) => {
  res.json({ results: [], query: req.query.q });
});

// ─────────────────────────────────────────────────────────────────────────────
// E-COMMERCE ROUTES
// ─────────────────────────────────────────────────────────────────────────────
const cartRouter = express.Router();

cartRouter.get   ('/',              fw('CART'),     (req, res) => {
  res.json({ items: [] });
});

cartRouter.post  ('/',              fw('CART'),     (req, res) => {
  res.json({ cart: { items: [req.body] } });
});

cartRouter.put   ('/:itemId',       fw('CART'),     (req, res) => {
  res.json({ cart: { item: req.body } });
});

cartRouter.delete('/:itemId',       fw('CART'),     (req, res) => {
  res.json({ removed: true });
});

app.use('/api/cart', cartRouter);

// Order routes
const orderRouter = express.Router();

orderRouter.get ('/',               fw('ORDER'),   (req, res) => {
  res.json({ orders: [] });
});

orderRouter.get ('/:id',            fw('ORDER'),   (req, res) => {
  res.json({ order: { id: req.params.id } });
});

orderRouter.post('/',               fw('PAYMENT'), (req, res) => {
  res.json({ order: { id: 1, ...req.body } });
});

app.use('/api/orders', orderRouter);

// Checkout
app.post('/api/checkout', fw('PAYMENT'), (req, res) => {
  res.json({ paymentUrl: 'https://payment-gateway.com/pay/xxx' });
});

// Coupon / Promo
app.post('/api/coupons/validate', fw('COUPON'), (req, res) => {
  res.json({ valid: true, discount: 10 });
});

// ─────────────────────────────────────────────────────────────────────────────
// PAYMENT ROUTES
// ─────────────────────────────────────────────────────────────────────────────
const paymentRouter = express.Router();

paymentRouter.post('/process',      fw('PAYMENT'),         (req, res) => {
  res.json({ transactionId: 'TXN-001', status: 'pending' });
});

paymentRouter.post('/webhook',      fw('PAYMENT_WEBHOOK'), (req, res) => {
  // SELALU verifikasi signature dari payment gateway!
  res.json({ received: true });
});

paymentRouter.post('/withdraw',     fw('WITHDRAW'),        (req, res) => {
  res.json({ withdrawalId: 'WD-001' });
});

app.use('/api/payment', paymentRouter);

// ─────────────────────────────────────────────────────────────────────────────
// CONTENT & MEDIA ROUTES
// ─────────────────────────────────────────────────────────────────────────────
const postRouter = express.Router();

postRouter.get ('/',                fw('PUBLIC_API'),      (req, res) => {
  res.json({ posts: [] });
});

postRouter.get ('/:id',             fw('PRODUCT_DETAIL'),  (req, res) => {
  res.json({ post: { id: req.params.id } });
});

postRouter.post('/',                fw('BLOG'),            (req, res) => {
  res.json({ post: req.body });
});

postRouter.put ('/:id',             fw('BLOG'),            (req, res) => {
  res.json({ post: req.body });
});

postRouter.delete('/:id',           fw('DELETE_DATA'),     (req, res) => {
  res.json({ deleted: true });
});

app.use('/api/posts', postRouter);

// Upload file / media
app.post('/api/upload', fw('MEDIA_UPLOAD'), (req, res) => {
  res.json({ url: 'https://cdn.example.com/media/file.jpg' });
});

// Comments
app.post('/api/comments',           fw('COMMENT'),         (req, res) => {
  res.json({ comment: req.body });
});

app.delete('/api/comments/:id',     fw('DELETE_DATA'),     (req, res) => {
  res.json({ deleted: true });
});

// Ratings
app.post('/api/ratings',            fw('RATING'),          (req, res) => {
  res.json({ rating: req.body });
});

// ─────────────────────────────────────────────────────────────────────────────
// COMMUNICATION ROUTES
// ─────────────────────────────────────────────────────────────────────────────

// Messaging
app.get ('/api/messages',           fw('MESSAGE'),         (req, res) => {
  res.json({ messages: [] });
});

app.post('/api/messages',           fw('MESSAGE'),         (req, res) => {
  res.json({ messageId: 1 });
});

// Contact form
app.post('/api/contact',            fw('CONTACT_FORM'),    (req, res) => {
  res.json({ sent: true });
});

// Newsletter
app.post('/api/newsletter/subscribe',   fw('NEWSLETTER'),  (req, res) => {
  res.json({ subscribed: true });
});

app.post('/api/newsletter/unsubscribe', fw('NEWSLETTER'),  (req, res) => {
  res.json({ unsubscribed: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// ADMIN ROUTES
// ─────────────────────────────────────────────────────────────────────────────
const adminRouter = express.Router();

adminRouter.post('/login',          fw('ADMIN_LOGIN'),     (req, res) => {
  res.json({ token: 'admin-token' });
});

adminRouter.get ('/users',          fw('ADMIN'),           (req, res) => {
  res.json({ users: [] });
});

adminRouter.put ('/users/:id',      fw('ADMIN'),           (req, res) => {
  res.json({ user: req.body });
});

adminRouter.post('/users/:id/ban',  fw('ADMIN'),           (req, res) => {
  res.json({ banned: true });
});

adminRouter.delete('/users/:id',    fw('ADMIN'),           (req, res) => {
  res.json({ deleted: true });
});

adminRouter.get ('/orders',         fw('ADMIN'),           (req, res) => {
  res.json({ orders: [] });
});

adminRouter.put ('/orders/:id',     fw('ADMIN'),           (req, res) => {
  res.json({ order: req.body });
});

adminRouter.get ('/products',       fw('ADMIN'),           (req, res) => {
  res.json({ products: [] });
});

adminRouter.post('/products/bulk',  fw('BULK'),            (req, res) => {
  res.json({ updated: (req.body.products || []).length });
});

adminRouter.get ('/analytics',      fw('ADMIN'),           (req, res) => {
  res.json({ analytics: {} });
});

adminRouter.get ('/logs',           fw('ADMIN'),           (req, res) => {
  res.json({ logs: [] });
});

app.use('/api/admin', adminRouter);

// ─────────────────────────────────────────────────────────────────────────────
// INTERNAL & WEBHOOK
// ─────────────────────────────────────────────────────────────────────────────
app.use('/api/internal', nextGuardExpress(ENDPOINT_PRESETS.INTERNAL_API), (req, res) => {
  res.json({ internal: true });
});

app.post('/api/webhooks/github',    fw('WEBHOOK'),         (req, res) => {
  res.json({ received: true });
});

app.post('/api/webhooks/slack',     fw('WEBHOOK'),         (req, res) => {
  res.json({ received: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// UTILITY ROUTES (tidak perlu proteksi berat)
// ─────────────────────────────────────────────────────────────────────────────

app.get('/health', fw('HEALTH_CHECK'), (req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

app.get('/api/public',  fw('PUBLIC_API'), (req, res) => {
  res.json({ data: [] });
});

// ─────────────────────────────────────────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[NextGuard] 🛡️  Server protected & running on http://localhost:${PORT}`);
  console.log('[NextGuard] All endpoints secured with appropriate firewall presets.');
});
