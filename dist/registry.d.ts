/**
 * NextGuard - Endpoint Registry
 *
 * Mencatat endpoint yang ditemukan secara otomatis dari request aktual.
 * BUKAN dari scanning source code atau konfigurasi manual.
 *
 * Key: "METHOD:path"  (e.g. "GET:/api/users", "POST:/api/upload")
 * Tidak pernah membuat duplikat untuk kombinasi METHOD+PATH yang sama.
 */
export interface EndpointRecord {
    /** Identifier unik: "METHOD:path" */
    id: string;
    method: string;
    path: string;
    /** Waktu pertama kali endpoint ini terlihat */
    firstSeen: number;
    /** Waktu terakhir kali endpoint ini menerima request */
    lastSeen: number;
    /** Total request yang masuk ke endpoint ini */
    requestCount: number;
    /** Request yang diblokir firewall */
    blockedCount: number;
    /** Request yang diizinkan melewati */
    allowedCount: number;
    /** Status code terakhir yang dikirim ke client */
    lastStatusCode: number;
    /** IP unik yang pernah mengakses endpoint ini (maks simpan 50) */
    uniqueIps: Set<string>;
}
export interface RegistryStats {
    totalEndpoints: number;
    totalRequests: number;
    totalBlocked: number;
    totalAllowed: number;
    endpoints: Omit<EndpointRecord, 'uniqueIps'>[];
}
/**
 * Normalize path: hapus query string, trailing slash, lowercase.
 * Contoh: "/api/Users?page=1" → "/api/users"
 */
export declare function normalizePath(rawUrl: string): string;
/**
 * Buat endpoint ID yang konsisten dari method + path.
 * Contoh: ("POST", "/api/Upload?foo=bar") → "POST:/api/upload"
 */
export declare function makeEndpointId(method: string, rawUrl: string): string;
export declare class EndpointRegistry {
    private records;
    /**
     * Catat request yang masuk.
     * Jika endpoint belum ada → buat baru.
     * Jika sudah ada → update counter saja (tidak duplikat).
     *
     * @param method HTTP method
     * @param rawUrl URL/path dari request (boleh query string, akan dinormalisasi)
     * @param ip Client IP
     * @param allowed Apakah request diizinkan melewati firewall
     * @param statusCode Status code yang dikirim
     * @returns EndpointRecord yang sudah diperbarui
     */
    record(method: string, rawUrl: string, ip: string, allowed: boolean, statusCode: number): EndpointRecord;
    /**
     * Ambil satu record berdasarkan id ("METHOD:path")
     */
    get(id: string): EndpointRecord | undefined;
    /**
     * Ambil semua endpoint yang sudah ditemukan
     */
    getAll(): EndpointRecord[];
    /**
     * Statistik ringkasan seluruh registry
     */
    getStats(): RegistryStats;
    /**
     * Hapus semua data (berguna untuk testing)
     */
    clear(): void;
    /**
     * Jumlah endpoint unik yang sudah diketahui
     */
    get size(): number;
}
//# sourceMappingURL=registry.d.ts.map