/**
 * Example: Redis Store untuk Distributed Rate Limiting
 *
 * Gunakan RedisStore jika aplikasi berjalan di multiple instances
 * (serverless, Kubernetes, load-balanced servers) agar rate limit
 * tersinkronisasi di seluruh instance.
 *
 * Install: npm install ioredis nextguard
 */

import { nextGuardExpress, RedisStore } from 'nextguard';
// import Redis from 'ioredis'; // uncomment in real usage

// Simulasi Redis client (ganti dengan ioredis/redis asli)
// const redis = new Redis(process.env.REDIS_URL);

// const firewall = nextGuardExpress({
//   rateLimit: {
//     windowMs: 60 * 1000,
//     max: 100,
//     store: new RedisStore({
//       client: redis,
//       prefix: 'myapp:nextguard:', // prefix key Redis
//     }),
//   },
//   sqlInjection: { enabled: true },
//   xss: { enabled: true },
// });

console.log('[Example] Redis Store integration loaded (demo mode)');

/**
 * RedisStore mendukung semua Redis-compatible clients:
 * - ioredis
 * - node-redis (redis package)
 * - Upstash Redis (Edge/Vercel)
 * - Dragonfly, KeyDB, Valkey
 */

export { RedisStore };
