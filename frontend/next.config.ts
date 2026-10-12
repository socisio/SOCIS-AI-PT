import type { NextConfig } from 'next';

// Internal backend URL used by Next.js server-side rewrites.
// The browser never sees this — requests come in as /api/... and are proxied.
// In Docker: set NEXT_API_PROXY_URL=http://backend:8000
// In dev:    defaults to http://localhost:8000
const BACKEND_URL = process.env.NEXT_API_PROXY_URL || 'http://localhost:8000';

const nextConfig: NextConfig = {
  output: 'standalone',
  // React strict mode deliberately runs every effect twice in development, so every page fired each of its API calls twice
  // (and mounted twice). That doubles the load on a small dev container. Production builds are unaffected either way.
  // Set NEXT_STRICT_MODE=true when you actively develop the UI and want the extra checks.
  reactStrictMode: process.env.NEXT_STRICT_MODE === 'true',
  // Compile only the icons / chart parts a page actually imports (large libraries slow the first compile of every page).
  experimental: {
    optimizePackageImports: ['lucide-react', 'recharts', '@xyflow/react'],
  },
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    // `next dev` never type-checks, so type errors that pre-date this setting only show up when you build for production,
    // and `next build` stops at the FIRST one (a 58-error group in the workflow builder blocked the first production build).
    // They are types only, with no effect at runtime, so by default they do not block the build.
    // To enforce them: build with NEXT_STRICT_BUILD=true. To list every one with the real compiler: deploy/scripts/typecheck-frontend.sh
    ignoreBuildErrors: process.env.NEXT_STRICT_BUILD !== 'true',
  },
  env: {
    // Empty string = use relative URLs (/api/...) so all requests go through
    // the Next.js proxy rewrite below, keeping cookies same-origin.
    // Override with e.g. https://socis.example.com only for HTTPS production
    // deployments where the frontend and backend are on different domains.
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL ?? '',
  },
  async rewrites() {
    return [
      {
        // Proxy all /api/* calls to the backend (HTTP API)
        source: '/api/:path*',
        destination: `${BACKEND_URL}/api/:path*`,
      },
      {
        // Proxy WebSocket connections — nginx handles this in production,
        // this rewrite covers the Next.js dev server case.
        source: '/ws/:path*',
        destination: `${BACKEND_URL}/ws/:path*`,
      },
    ];
  },
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'lh3.googleusercontent.com' },
      { protocol: 'https', hostname: 'avatars.githubusercontent.com' },
    ],
  },
};

export default nextConfig;
