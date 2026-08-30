import { defineConfig } from 'vitest/config';

/**
 * Resolve the `.js` specifiers that ESM-correct TypeScript sources use back to
 * the `.ts` files on disk, so tests exercise `src` directly rather than a build
 * artifact.
 */
const resolveTsFromJs = {
  name: 'kh-sqr:resolve-ts-from-js',
  enforce: 'pre' as const,
  async resolveId(source: string, importer: string | undefined) {
    if (importer === undefined || !source.startsWith('.') || !source.endsWith('.js')) return null;
    const candidate = new URL(source.replace(/\.js$/, '.ts'), `file://${importer}`).pathname;
    const resolved = await this.resolve(candidate, importer, { skipSelf: true });
    return resolved ?? null;
  },
};

export default defineConfig({
  plugins: [resolveTsFromJs],
  test: {
    include: ['packages/**/test/**/*.test.ts'],
    environment: 'node',
  },
});
