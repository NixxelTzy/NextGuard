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
export function normalizePath(rawUrl: string): string {
  try {
    // Jika URL lengkap (http://...), parse dengan URL API
    const urlObj = rawUrl.startsWith('http')
      ? new URL(rawUrl)
      : new URL(`http://localhost${rawUrl}`);

    let pathname = urlObj.pathname;

    // Hapus trailing slash kecuali root "/"
    if (pathname.length > 1 && pathname.endsWith('/')) {
      pathname = pathname.slice(0, -1);
    }

    return pathname.toLowerCase();
  } catch {
    // Fallback: hapus query string secara manual
    return rawUrl.split('?')[0].split('#')[0].toLowerCase() || '/';
  }
}

/**
 * Buat endpoint ID yang konsisten dari method + path.
 * Contoh: ("POST", "/api/Upload?foo=bar") → "POST:/api/upload"
 */
export function makeEndpointId(method: string, rawUrl: string): string {
  return `${method.toUpperCase()}:${normalizePath(rawUrl)}`;
}

const MAX_UNIQUE_IPS = 50;

export class EndpointRegistry {
  private records: Map<string, EndpointRecord> = new Map();

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
  public record(
    method: string,
    rawUrl: string,
    ip: string,
    allowed: boolean,
    statusCode: number
  ): EndpointRecord {
    const path = normalizePath(rawUrl);
    const id = `${method.toUpperCase()}:${path}`;
    const now = Date.now();

    let rec = this.records.get(id);

    if (!rec) {
      // Endpoint baru — buat entry pertama kali
      rec = {
        id,
        method: method.toUpperCase(),
        path,
        firstSeen: now,
        lastSeen: now,
        requestCount: 0,
        blockedCount: 0,
        allowedCount: 0,
        lastStatusCode: statusCode,
        uniqueIps: new Set(),
      };
      this.records.set(id, rec);
    }

    // Update statistik
    rec.lastSeen = now;
    rec.requestCount++;
    rec.lastStatusCode = statusCode;

    if (allowed) {
      rec.allowedCount++;
    } else {
      rec.blockedCount++;
    }

    // Simpan IP unik (batasi agar tidak tumbuh tak terbatas)
    if (rec.uniqueIps.size < MAX_UNIQUE_IPS) {
      rec.uniqueIps.add(ip);
    }

    return rec;
  }

  /**
   * Ambil satu record berdasarkan id ("METHOD:path")
   */
  public get(id: string): EndpointRecord | undefined {
    return this.records.get(id);
  }

  /**
   * Ambil semua endpoint yang sudah ditemukan
   */
  public getAll(): EndpointRecord[] {
    return Array.from(this.records.values());
  }

  /**
   * Statistik ringkasan seluruh registry
   */
  public getStats(): RegistryStats {
    const endpoints = this.getAll();
    return {
      totalEndpoints: endpoints.length,
      totalRequests: endpoints.reduce((s, e) => s + e.requestCount, 0),
      totalBlocked: endpoints.reduce((s, e) => s + e.blockedCount, 0),
      totalAllowed: endpoints.reduce((s, e) => s + e.allowedCount, 0),
      endpoints: endpoints.map(({ uniqueIps, ...rest }) => ({
        ...rest,
        uniqueIpCount: uniqueIps.size,
      })) as any,
    };
  }

  /**
   * Hapus semua data (berguna untuk testing)
   */
  public clear(): void {
    this.records.clear();
  }

  /**
   * Jumlah endpoint unik yang sudah diketahui
   */
  public get size(): number {
    return this.records.size;
  }
}
