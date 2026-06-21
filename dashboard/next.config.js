/** @type {import('next').NextConfig} */
const nextConfig = {
  // Emit a self-contained server bundle so the Docker runtime image needs only
  // the .next/standalone output + node — no node_modules copy, no `next start`.
  output: 'standalone',
  // The dashboard is an internal ops tool; no need to leak the framework header.
  poweredByHeader: false,
  reactStrictMode: true,
};

module.exports = nextConfig;
