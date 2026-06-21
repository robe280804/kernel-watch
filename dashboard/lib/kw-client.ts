// Server-only client for the KernelWatch REST API. This module must never be
// imported from a Client Component: it reads KW_API_TOKEN from the server
// environment and injects it as a Bearer header. The browser only ever talks to
// this dashboard's own /api/* route handlers, which call through here — so the
// token stays server-side.
import 'server-only';

const API_URL = process.env.KW_API_URL ?? 'http://127.0.0.1:8080';
const API_TOKEN = process.env.KW_API_TOKEN ?? '';
const TIMEOUT_MS = 10_000;

export interface KwResult<T> {
  ok: boolean;
  status: number;
  data: T | null;
  error?: string;
}

// request proxies a single call to the KernelWatch API and normalizes the
// outcome into a KwResult so route handlers can pass status + body straight
// back to the browser without leaking transport details.
async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<KwResult<T>> {
  if (!API_TOKEN) {
    return {
      ok: false,
      status: 500,
      data: null,
      error:
        'dashboard is missing KW_API_TOKEN — set it in the environment (it must match the daemon token)',
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${API_URL}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${API_TOKEN}`,
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
      cache: 'no-store',
    });

    // 204 No Content (successful DELETE) has no body to parse.
    if (res.status === 204) {
      return { ok: true, status: 204, data: null };
    }

    const text = await res.text();
    let parsed: unknown = null;
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        return {
          ok: false,
          status: res.status,
          data: null,
          error: 'upstream returned a non-JSON response',
        };
      }
    }

    if (!res.ok) {
      const msg =
        (parsed as { error?: string } | null)?.error ?? `upstream status ${res.status}`;
      return { ok: false, status: res.status, data: null, error: msg };
    }
    return { ok: true, status: res.status, data: parsed as T };
  } catch (err) {
    const aborted = err instanceof Error && err.name === 'AbortError';
    return {
      ok: false,
      status: aborted ? 504 : 502,
      data: null,
      error: aborted
        ? 'timed out contacting the KernelWatch API'
        : `cannot reach the KernelWatch API at ${API_URL} (is KW_API_ENABLED=true?)`,
    };
  } finally {
    clearTimeout(timer);
  }
}

export function kwGet<T>(path: string) {
  return request<T>('GET', path);
}

export function kwPost<T>(path: string, body: unknown) {
  return request<T>('POST', path, body);
}

export function kwDelete<T>(path: string) {
  return request<T>('DELETE', path);
}
