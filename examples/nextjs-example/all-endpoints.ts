/**
 * NextGuard - Contoh Penggunaan Semua Endpoint (Next.js App Router)
 *
 * Setiap endpoint dilindungi dengan konfigurasi firewall
 * yang sudah disesuaikan menggunakan ENDPOINT_PRESETS.
 *
 * Cara paling mudah:
 *   import { withNextGuard, ENDPOINT_PRESETS } from 'nextguard';
 *   export const POST = withNextGuard(handler, ENDPOINT_PRESETS.LOGIN);
 */

import { withNextGuard, ENDPOINT_PRESETS } from 'nextguard';

// ─────────────────────────────────────────────────────────────────────────────
// AUTENTIKASI
// ─────────────────────────────────────────────────────────────────────────────

// app/api/auth/login/route.ts
async function loginHandler(req: Request) {
  const { email, password } = await req.json();
  return Response.json({ token: 'jwt-token-here' });
}
export const login_POST = withNextGuard(loginHandler, ENDPOINT_PRESETS.LOGIN);

// app/api/auth/register/route.ts
async function registerHandler(req: Request) {
  const data = await req.json();
  return Response.json({ user: { id: 1, ...data } });
}
export const register_POST = withNextGuard(registerHandler, ENDPOINT_PRESETS.REGISTER);

// app/api/auth/logout/route.ts
async function logoutHandler(req: Request) {
  return Response.json({ success: true });
}
export const logout_POST = withNextGuard(logoutHandler, ENDPOINT_PRESETS.LOGOUT);

// app/api/auth/forgot-password/route.ts
async function forgotPasswordHandler(req: Request) {
  const { email } = await req.json();
  return Response.json({ message: 'Email reset dikirim' });
}
export const forgotPassword_POST = withNextGuard(forgotPasswordHandler, ENDPOINT_PRESETS.FORGOT_PASSWORD);

// app/api/auth/change-password/route.ts
async function changePasswordHandler(req: Request) {
  const { oldPassword, newPassword } = await req.json();
  return Response.json({ success: true });
}
export const changePassword_POST = withNextGuard(changePasswordHandler, ENDPOINT_PRESETS.CHANGE_PASSWORD);

// app/api/auth/verify-otp/route.ts
async function verifyOtpHandler(req: Request) {
  const { otp } = await req.json();
  return Response.json({ verified: true });
}
export const verifyOtp_POST = withNextGuard(verifyOtpHandler, ENDPOINT_PRESETS.VERIFY_OTP);

// app/api/auth/refresh/route.ts
async function tokenRefreshHandler(req: Request) {
  const { refreshToken } = await req.json();
  return Response.json({ token: 'new-token' });
}
export const tokenRefresh_POST = withNextGuard(tokenRefreshHandler, ENDPOINT_PRESETS.TOKEN_REFRESH);

// app/api/auth/oauth/callback/route.ts
async function oauthCallbackHandler(req: Request) {
  const { searchParams } = new URL(req.url);
  const code = searchParams.get('code');
  return Response.json({ user: {} });
}
export const oauthCallback_GET = withNextGuard(oauthCallbackHandler, ENDPOINT_PRESETS.OAUTH_CALLBACK);

// ─────────────────────────────────────────────────────────────────────────────
// PROFIL PENGGUNA
// ─────────────────────────────────────────────────────────────────────────────

// app/api/user/profile/route.ts
async function getProfileHandler(req: Request) {
  return Response.json({ user: { id: 1, name: 'John' } });
}
export const getProfile_GET = withNextGuard(getProfileHandler, ENDPOINT_PRESETS.PROFILE);

async function updateProfileHandler(req: Request) {
  const data = await req.json();
  return Response.json({ user: data });
}
export const updateProfile_PUT = withNextGuard(updateProfileHandler, ENDPOINT_PRESETS.PROFILE);

// app/api/user/avatar/route.ts
async function uploadAvatarHandler(req: Request) {
  return Response.json({ url: 'https://cdn.example.com/avatar.jpg' });
}
export const uploadAvatar_POST = withNextGuard(uploadAvatarHandler, ENDPOINT_PRESETS.FILE_UPLOAD);

// ─────────────────────────────────────────────────────────────────────────────
// PRODUK & KATALOG
// ─────────────────────────────────────────────────────────────────────────────

// app/api/products/route.ts
async function listProductsHandler(req: Request) {
  const { searchParams } = new URL(req.url);
  const page = searchParams.get('page') || '1';
  return Response.json({ products: [], page });
}
export const listProducts_GET = withNextGuard(listProductsHandler, ENDPOINT_PRESETS.PRODUCTS);

async function createProductHandler(req: Request) {
  const data = await req.json();
  return Response.json({ product: { id: 1, ...data } });
}
export const createProduct_POST = withNextGuard(createProductHandler, ENDPOINT_PRESETS.CREATE_UPDATE);

// app/api/products/[id]/route.ts
async function getProductHandler(req: Request) {
  const id = req.url.split('/').pop();
  return Response.json({ product: { id } });
}
export const getProduct_GET = withNextGuard(getProductHandler, ENDPOINT_PRESETS.PRODUCT_DETAIL);

async function updateProductHandler(req: Request) {
  const data = await req.json();
  return Response.json({ product: data });
}
export const updateProduct_PUT = withNextGuard(updateProductHandler, ENDPOINT_PRESETS.CREATE_UPDATE);

async function deleteProductHandler(req: Request) {
  return Response.json({ deleted: true });
}
export const deleteProduct_DELETE = withNextGuard(deleteProductHandler, ENDPOINT_PRESETS.DELETE_DATA);

// app/api/search/route.ts
async function searchHandler(req: Request) {
  const { searchParams } = new URL(req.url);
  const q = searchParams.get('q') || '';
  return Response.json({ results: [], query: q });
}
export const search_GET = withNextGuard(searchHandler, ENDPOINT_PRESETS.SEARCH);

// ─────────────────────────────────────────────────────────────────────────────
// E-COMMERCE
// ─────────────────────────────────────────────────────────────────────────────

// app/api/cart/route.ts
async function getCartHandler(req: Request) {
  return Response.json({ items: [] });
}
export const getCart_GET = withNextGuard(getCartHandler, ENDPOINT_PRESETS.CART);

async function addToCartHandler(req: Request) {
  const { productId, quantity } = await req.json();
  return Response.json({ cart: { items: [{ productId, quantity }] } });
}
export const addToCart_POST = withNextGuard(addToCartHandler, ENDPOINT_PRESETS.CART);

// app/api/cart/[itemId]/route.ts
async function removeFromCartHandler(req: Request) {
  return Response.json({ removed: true });
}
export const removeFromCart_DELETE = withNextGuard(removeFromCartHandler, ENDPOINT_PRESETS.CART);

// app/api/orders/route.ts
async function listOrdersHandler(req: Request) {
  return Response.json({ orders: [] });
}
export const listOrders_GET = withNextGuard(listOrdersHandler, ENDPOINT_PRESETS.ORDER);

async function createOrderHandler(req: Request) {
  const data = await req.json();
  return Response.json({ order: { id: 1, ...data } });
}
export const createOrder_POST = withNextGuard(createOrderHandler, ENDPOINT_PRESETS.PAYMENT);

// app/api/checkout/route.ts
async function checkoutHandler(req: Request) {
  const { items, paymentMethod } = await req.json();
  return Response.json({ paymentUrl: 'https://payment-gateway.com/pay/xxx' });
}
export const checkout_POST = withNextGuard(checkoutHandler, ENDPOINT_PRESETS.PAYMENT);

// app/api/coupons/validate/route.ts
async function validateCouponHandler(req: Request) {
  const { code } = await req.json();
  return Response.json({ valid: true, discount: 10 });
}
export const validateCoupon_POST = withNextGuard(validateCouponHandler, ENDPOINT_PRESETS.COUPON);

// ─────────────────────────────────────────────────────────────────────────────
// PEMBAYARAN
// ─────────────────────────────────────────────────────────────────────────────

// app/api/payment/process/route.ts
async function processPaymentHandler(req: Request) {
  const { amount, method } = await req.json();
  return Response.json({ transactionId: 'TXN-001', status: 'pending' });
}
export const processPayment_POST = withNextGuard(processPaymentHandler, ENDPOINT_PRESETS.PAYMENT);

// app/api/payment/webhook/route.ts
async function paymentWebhookHandler(req: Request) {
  const payload = await req.json();
  // Verifikasi signature dari payment gateway di sini!
  return Response.json({ received: true });
}
export const paymentWebhook_POST = withNextGuard(paymentWebhookHandler, ENDPOINT_PRESETS.PAYMENT_WEBHOOK);

// app/api/wallet/withdraw/route.ts
async function withdrawHandler(req: Request) {
  const { amount, bankAccount } = await req.json();
  return Response.json({ withdrawalId: 'WD-001' });
}
export const withdraw_POST = withNextGuard(withdrawHandler, ENDPOINT_PRESETS.WITHDRAW);

// ─────────────────────────────────────────────────────────────────────────────
// KONTEN & MEDIA
// ─────────────────────────────────────────────────────────────────────────────

// app/api/posts/route.ts
async function listPostsHandler(req: Request) {
  return Response.json({ posts: [] });
}
export const listPosts_GET = withNextGuard(listPostsHandler, ENDPOINT_PRESETS.PRODUCTS);

async function createPostHandler(req: Request) {
  const data = await req.json();
  return Response.json({ post: data });
}
export const createPost_POST = withNextGuard(createPostHandler, ENDPOINT_PRESETS.BLOG);

async function updatePostHandler(req: Request) {
  const data = await req.json();
  return Response.json({ post: data });
}
export const updatePost_PUT = withNextGuard(updatePostHandler, ENDPOINT_PRESETS.BLOG);

// app/api/upload/route.ts
async function uploadHandler(req: Request) {
  return Response.json({ url: 'https://cdn.example.com/file.jpg' });
}
export const upload_POST = withNextGuard(uploadHandler, ENDPOINT_PRESETS.MEDIA_UPLOAD);

// app/api/comments/route.ts
async function createCommentHandler(req: Request) {
  const { content, postId } = await req.json();
  return Response.json({ comment: { id: 1, content, postId } });
}
export const createComment_POST = withNextGuard(createCommentHandler, ENDPOINT_PRESETS.COMMENT);

// app/api/ratings/route.ts
async function createRatingHandler(req: Request) {
  const { rating, review, productId } = await req.json();
  return Response.json({ rating: { id: 1, rating, review, productId } });
}
export const createRating_POST = withNextGuard(createRatingHandler, ENDPOINT_PRESETS.RATING);

// ─────────────────────────────────────────────────────────────────────────────
// KOMUNIKASI
// ─────────────────────────────────────────────────────────────────────────────

// app/api/messages/route.ts
async function sendMessageHandler(req: Request) {
  const { to, content } = await req.json();
  return Response.json({ messageId: 1 });
}
export const sendMessage_POST = withNextGuard(sendMessageHandler, ENDPOINT_PRESETS.MESSAGE);

// app/api/contact/route.ts
async function contactFormHandler(req: Request) {
  const { name, email, message } = await req.json();
  return Response.json({ sent: true });
}
export const contactForm_POST = withNextGuard(contactFormHandler, ENDPOINT_PRESETS.CONTACT_FORM);

// app/api/newsletter/subscribe/route.ts
async function subscribeHandler(req: Request) {
  const { email } = await req.json();
  return Response.json({ subscribed: true });
}
export const subscribe_POST = withNextGuard(subscribeHandler, ENDPOINT_PRESETS.NEWSLETTER);

async function unsubscribeHandler(req: Request) {
  const { email } = await req.json();
  return Response.json({ unsubscribed: true });
}
export const unsubscribe_POST = withNextGuard(unsubscribeHandler, ENDPOINT_PRESETS.NEWSLETTER);

// ─────────────────────────────────────────────────────────────────────────────
// ADMIN
// ─────────────────────────────────────────────────────────────────────────────

// app/api/admin/login/route.ts
async function adminLoginHandler(req: Request) {
  const { username, password } = await req.json();
  return Response.json({ token: 'admin-token' });
}
export const adminLogin_POST = withNextGuard(adminLoginHandler, ENDPOINT_PRESETS.ADMIN_LOGIN);

// app/api/admin/users/route.ts
async function listUsersAdminHandler(req: Request) {
  return Response.json({ users: [] });
}
export const listUsersAdmin_GET = withNextGuard(listUsersAdminHandler, ENDPOINT_PRESETS.ADMIN);

async function banUserHandler(req: Request) {
  const { userId, reason } = await req.json();
  return Response.json({ banned: true });
}
export const banUser_POST = withNextGuard(banUserHandler, ENDPOINT_PRESETS.ADMIN);

// app/api/admin/orders/route.ts
async function listOrdersAdminHandler(req: Request) {
  return Response.json({ orders: [] });
}
export const listOrdersAdmin_GET = withNextGuard(listOrdersAdminHandler, ENDPOINT_PRESETS.ADMIN);

// app/api/admin/products/bulk/route.ts
async function bulkProductsHandler(req: Request) {
  const { products } = await req.json();
  return Response.json({ updated: products.length });
}
export const bulkProducts_POST = withNextGuard(bulkProductsHandler, ENDPOINT_PRESETS.BULK);

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIK & UTILITY
// ─────────────────────────────────────────────────────────────────────────────

// app/api/health/route.ts
async function healthCheckHandler(req: Request) {
  return Response.json({ status: 'ok', timestamp: Date.now() });
}
export const healthCheck_GET = withNextGuard(healthCheckHandler, ENDPOINT_PRESETS.HEALTH_CHECK);

// app/api/v1/public/route.ts
async function publicApiHandler(req: Request) {
  return Response.json({ data: [] });
}
export const publicApi_GET = withNextGuard(publicApiHandler, ENDPOINT_PRESETS.PUBLIC_API);

// app/api/webhook/route.ts (webhook umum - e.g. GitHub, Slack)
async function genericWebhookHandler(req: Request) {
  const payload = await req.json();
  return Response.json({ received: true });
}
export const genericWebhook_POST = withNextGuard(genericWebhookHandler, ENDPOINT_PRESETS.WEBHOOK);

// app/api/keys/route.ts
async function manageApiKeysHandler(req: Request) {
  return Response.json({ keys: [] });
}
export const manageApiKeys_GET = withNextGuard(manageApiKeysHandler, ENDPOINT_PRESETS.API_KEY);
