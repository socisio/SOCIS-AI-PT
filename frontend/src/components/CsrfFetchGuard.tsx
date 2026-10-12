'use client';

import { useEffect } from 'react';

/**
 * CSRF defense-in-depth (fix L-9).
 *
 * Installs a one-time global `fetch` wrapper that attaches the
 * `X-Requested-With: SOCIS` header to all same-origin API requests. The
 * backend requires this header on cookie-authenticated, state-changing
 * requests; because browsers will not attach a custom header to a cross-site
 * forged request without a CORS preflight (which the strict server-side origin
 * allowlist refuses), a forged request from another site is rejected.
 *
 * This covers every raw `fetch()` call site in the app without having to edit
 * each one. The shared axios client sets the same header via its defaults.
 */
export default function CsrfFetchGuard() {
  useEffect(() => {
    const w = window as unknown as { __socisFetchPatched?: boolean };
    if (w.__socisFetchPatched) return;
    w.__socisFetchPatched = true;

    const originalFetch = window.fetch.bind(window);
    window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
      try {
        // Only add the header for same-origin / relative requests.
        let sameOrigin = true;
        const url =
          typeof input === 'string'
            ? input
            : input instanceof URL
              ? input.toString()
              : (input as Request).url;
        if (/^https?:\/\//i.test(url)) {
          sameOrigin = url.startsWith(window.location.origin);
        }
        if (sameOrigin) {
          const headers = new Headers(init?.headers || {});
          if (!headers.has('X-Requested-With')) {
            headers.set('X-Requested-With', 'SOCIS');
          }
          init = { ...init, headers };
        }
      } catch {
        /* fall through to the original call */
      }
      return originalFetch(input, init);
    };
  }, []);

  return null;
}
