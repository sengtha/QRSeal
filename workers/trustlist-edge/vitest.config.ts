import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

/**
 * Tests run inside workerd, not a Node shim. The crypto and stream behaviour
 * this project depends on must be the real runtime's.
 */
export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: './wrangler.toml' } })],
  test: { include: ['test/**/*.test.ts'] },
});
