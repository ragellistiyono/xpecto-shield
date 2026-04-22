import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  transpilePackages: ['xpecto-shield'],
  serverExternalPackages: ['fs', 'path'],
}

export default nextConfig
