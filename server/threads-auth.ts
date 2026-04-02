import type { Request, Response, NextFunction } from 'express';
import type { IncomingMessage } from 'http';

// ── Types ──────────────────────────────────────────────────────────────────────

export interface ThreadsUser {
  id: number | string;
  username: string;
  display_name: string | null;
}

declare global {
  namespace Express {
    interface Request {
      threadsUser?: ThreadsUser;
    }
  }
}

// ── Configuration ──────────────────────────────────────────────────────────────

const THREADS_API_URL = (process.env.THREADS_API_URL || 'https://threads-api.filae.site').replace(/\/+$/, '');
const PROOF_API_KEY = process.env.PROOF_API_KEY || '';
const SESSION_COOKIE_NAME = 'session';
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// ── Session cache ──────────────────────────────────────────────────────────────

interface CachedSession {
  user: ThreadsUser;
  expiresAt: number;
}

const sessionCache = new Map<string, CachedSession>();

function getCachedUser(token: string): ThreadsUser | null {
  const cached = sessionCache.get(token);
  if (!cached) return null;
  if (Date.now() > cached.expiresAt) {
    sessionCache.delete(token);
    return null;
  }
  return cached.user;
}

function cacheUser(token: string, user: ThreadsUser): void {
  sessionCache.set(token, { user, expiresAt: Date.now() + CACHE_TTL_MS });
}

// Periodically prune expired entries so the map doesn't grow unbounded.
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of sessionCache) {
    if (now > entry.expiresAt) sessionCache.delete(key);
  }
}, CACHE_TTL_MS).unref();

// ── Token extraction helpers ───────────────────────────────────────────────────

function extractSessionToken(req: Request): string | null {
  // 1. Authorization: Bearer <token>
  const authHeader = req.header('authorization');
  if (authHeader) {
    const match = authHeader.match(/^Bearer\s+(\S+)$/i);
    if (match) return match[1]!;
  }

  // 2. session cookie
  const cookieHeader = req.header('cookie');
  return parseCookieValue(cookieHeader, SESSION_COOKIE_NAME);
}

/** Extract the session cookie or Authorization bearer token from a raw IncomingMessage (for WS upgrade). */
function extractSessionTokenFromRaw(req: IncomingMessage): string | null {
  // 1. Authorization: Bearer <token>
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const match = authHeader.match(/^Bearer\s+(\S+)$/i);
    if (match) return match[1]!;
  }

  // 2. session cookie
  const cookieHeader = req.headers.cookie;
  return parseCookieValue(cookieHeader, SESSION_COOKIE_NAME);
}

function parseCookieValue(cookieHeader: string | undefined | null, name: string): string | null {
  if (typeof cookieHeader !== 'string' || !cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    if (trimmed.slice(0, eq).trim() === name) {
      return trimmed.slice(eq + 1).trim();
    }
  }
  return null;
}

// ── Validation against Threads API ─────────────────────────────────────────────

async function validateWithThreadsApi(token: string): Promise<ThreadsUser | null> {
  try {
    const response = await fetch(`${THREADS_API_URL}/users/me`, {
      headers: { cookie: `${SESSION_COOKIE_NAME}=${token}` },
    });
    if (!response.ok) return null;
    const data = (await response.json()) as Record<string, unknown>;
    if (typeof data.id !== 'number' || typeof data.username !== 'string') return null;
    return {
      id: data.id,
      username: data.username,
      display_name: typeof data.display_name === 'string' ? data.display_name : null,
    };
  } catch (error) {
    console.error('[threads-auth] failed to validate session with Threads API', error);
    return null;
  }
}

// ── Static API key check ───────────────────────────────────────────────────────

function isValidApiKey(req: Request): boolean {
  if (!PROOF_API_KEY) return false;
  const authHeader = req.header('authorization');
  if (!authHeader) return false;
  const match = authHeader.match(/^Bearer\s+(\S+)$/i);
  return match?.[1] === PROOF_API_KEY;
}

// ── Express middleware ─────────────────────────────────────────────────────────

export function threadsAuthMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Static API key bypass — trusted agent/service access
  if (PROOF_API_KEY && isValidApiKey(req)) {
    req.threadsUser = { id: 'api-key', username: 'api-key', display_name: 'API Key' };
    next();
    return;
  }

  const token = extractSessionToken(req);
  if (!token) {
    // Soft middleware: allow the request through without auth.
    // Routes that need Threads auth can check req.threadsUser themselves.
    next();
    return;
  }

  // Check cache first
  const cached = getCachedUser(token);
  if (cached) {
    req.threadsUser = cached;
    next();
    return;
  }

  // Validate against Threads API — attach user if valid, pass through regardless
  validateWithThreadsApi(token).then((user) => {
    if (user) {
      cacheUser(token, user);
      req.threadsUser = user;
    }
    next();
  }).catch(() => {
    // Auth service unavailable — let the request through without user info
    next();
  });
}

/** Hard auth gate — rejects 401 if no Threads user attached. */
export function requireThreadsAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.threadsUser) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  next();
}

// ── WebSocket upgrade auth ─────────────────────────────────────────────────────

/**
 * Validate a raw IncomingMessage (WS upgrade request) against Threads session auth.
 * Returns the user on success, null on failure.
 */
export async function authenticateWsUpgrade(req: IncomingMessage): Promise<ThreadsUser | null> {
  // Check API key first
  if (PROOF_API_KEY) {
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const match = authHeader.match(/^Bearer\s+(\S+)$/i);
      if (match?.[1] === PROOF_API_KEY) {
        return { id: 'api-key', username: 'api-key', display_name: 'API Key' };
      }
    }
  }

  const token = extractSessionTokenFromRaw(req);
  if (!token) return null;

  const cached = getCachedUser(token);
  if (cached) return cached;

  const user = await validateWithThreadsApi(token);
  if (user) cacheUser(token, user);
  return user;
}
