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
export declare const ENDPOINT_PRESETS: {
    readonly LOGIN: NextGuardConfig;
    readonly REGISTER: NextGuardConfig;
    readonly LOGOUT: NextGuardConfig;
    readonly FORGOT_PASSWORD: NextGuardConfig;
    readonly CHANGE_PASSWORD: NextGuardConfig;
    readonly VERIFY_OTP: NextGuardConfig;
    readonly OAUTH_CALLBACK: NextGuardConfig;
    readonly TOKEN_REFRESH: NextGuardConfig;
    readonly API_KEY: NextGuardConfig;
    readonly PROFILE: NextGuardConfig;
    readonly FILE_UPLOAD: NextGuardConfig;
    readonly COMMENT: NextGuardConfig;
    readonly MESSAGE: NextGuardConfig;
    readonly SEARCH: NextGuardConfig;
    readonly PRODUCTS: NextGuardConfig;
    readonly PRODUCT_DETAIL: NextGuardConfig;
    readonly CREATE_UPDATE: NextGuardConfig;
    readonly DELETE_DATA: NextGuardConfig;
    readonly BULK: NextGuardConfig;
    readonly PAYMENT: NextGuardConfig;
    readonly PAYMENT_WEBHOOK: NextGuardConfig;
    readonly WITHDRAW: NextGuardConfig;
    readonly ADMIN: NextGuardConfig;
    readonly ADMIN_LOGIN: NextGuardConfig;
    readonly INTERNAL_API: NextGuardConfig;
    readonly WEBHOOK: NextGuardConfig;
    readonly CART: NextGuardConfig;
    readonly ORDER: NextGuardConfig;
    readonly COUPON: NextGuardConfig;
    readonly RATING: NextGuardConfig;
    readonly MEDIA_UPLOAD: NextGuardConfig;
    readonly BLOG: NextGuardConfig;
    readonly PUBLIC_API: NextGuardConfig;
    readonly HEALTH_CHECK: NextGuardConfig;
    readonly SEO: NextGuardConfig;
    readonly NEWSLETTER: NextGuardConfig;
    readonly CONTACT_FORM: NextGuardConfig;
};
export type EndpointPresetKey = keyof typeof ENDPOINT_PRESETS;
//# sourceMappingURL=presets.d.ts.map