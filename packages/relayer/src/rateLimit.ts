// In-memory per-IP token bucket. One submit per IP per `windowMs`. Demo
// scale; not safe across a process restart or behind multiple replicas.

export interface RateLimiter {
    take(ip: string, now?: number): boolean;
}

export function makeRateLimiter(windowMs: number): RateLimiter {
    const lastHit = new Map<string, number>();
    return {
        take(ip: string, now: number = Date.now()): boolean {
            const prev = lastHit.get(ip);
            if (prev !== undefined && now - prev < windowMs) return false;
            lastHit.set(ip, now);
            // opportunistic GC: prune entries older than 10 windows so the
            // map can't grow unbounded if the process runs for ages.
            if (lastHit.size > 10_000) {
                const cutoff = now - windowMs * 10;
                for (const [k, v] of lastHit) {
                    if (v < cutoff) lastHit.delete(k);
                }
            }
            return true;
        },
    };
}
