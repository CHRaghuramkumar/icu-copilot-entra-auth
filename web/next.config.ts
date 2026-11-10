import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // Pin the workspace root to this folder so a package-lock.json higher up
  // (e.g. in your home directory) is not picked as the project root.
  turbopack: { root: __dirname },
};

export default nextConfig;
