/**
 * Next.js configuration.
 *
 * The settings that matter here are the ones that keep the build self-contained.
 * See docs/11-air-gap.md: the deployment target has no route off the host, so a
 * remote image loader or a font fetch is not a performance choice, it is a
 * broken install.
 */

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,

  // Standalone output so the container does not need a package install at run
  // time, which would be a network call.
  output: 'standalone',

  images: {
    // No remote patterns. Every image is bundled.
    remotePatterns: [],
    unoptimized: true,
  },

  // No telemetry, no update check, no external asset host. Anything added here
  // that names a host outside the deployment fails the air-gap CI job.
  headers: async () => [
    {
      source: '/:path*',
      headers: [
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'X-Frame-Options', value: 'DENY' },
        { key: 'Referrer-Policy', value: 'no-referrer' },
        {
          key: 'Content-Security-Policy',
          value: "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'",
        },
      ],
    },
  ],
};

export default nextConfig;
