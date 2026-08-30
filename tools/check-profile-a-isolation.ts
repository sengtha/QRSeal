/**
 * Fail the build if Profile A's transitive import graph reaches CBOR, any
 * stream API, or anything else outside Web Crypto.
 *
 * The point is embeddability: a mobile wallet must be able to take Profile A
 * verification and nothing else, with no polyfill. That property is invisible
 * in the type system and easy to lose in a refactor, so it is asserted here.
 */

import { readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = join(ROOT, 'packages', 'core', 'src', 'profileA.ts');

/** Modules Profile A must never reach, directly or transitively. */
const FORBIDDEN_MODULES = ['cbor.ts', 'cose.ts', 'profileB.ts', 'base45.ts'];

/**
 * Identifiers that imply a runtime capability beyond Web Crypto. `crypto` and
 * `TextEncoder` are deliberately absent: Web Crypto is the permitted floor,
 * and Profile A encodes ASCII by hand rather than using TextEncoder.
 */
const FORBIDDEN_GLOBALS = [
  'CompressionStream',
  'DecompressionStream',
  'ReadableStream',
  'WritableStream',
  'TransformStream',
  'Blob',
  'Response',
  'Request',
  'fetch',
  'XMLHttpRequest',
  'WebSocket',
  'require(',
  'node:',
];

const IMPORT_PATTERN = /(?:^|\n)\s*(?:import|export)[\s\S]*?from\s+['"]([^'"]+)['"]/g;

function importsOf(source: string): string[] {
  const found: string[] = [];
  for (const match of source.matchAll(IMPORT_PATTERN)) {
    const specifier = match[1];
    if (specifier !== undefined) found.push(specifier);
  }
  return found;
}

const visited = new Set<string>();
const failures: string[] = [];

function walk(file: string, chain: readonly string[]): void {
  if (visited.has(file)) return;
  visited.add(file);

  const source = readFileSync(file, 'utf8');
  const where = [...chain, relative(ROOT, file)].join(' -> ');

  // Comments describe the rule; only code should be searched for violations.
  const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');

  for (const global of FORBIDDEN_GLOBALS) {
    // Identifier-shaped entries are matched on word boundaries so that
    // `fetchedAt` is not mistaken for `fetch`.
    const pattern = /^[A-Za-z_$][\w$]*$/.test(global)
      ? new RegExp(`\\b${global}\\b`)
      : null;
    const hit = pattern === null ? code.includes(global) : pattern.test(code);
    if (hit) failures.push(`${where}: references \`${global}\``);
  }

  for (const specifier of importsOf(code)) {
    if (!specifier.startsWith('.')) {
      // A type-only import of a sibling is fine; a package import is not.
      failures.push(`${where}: imports the package \`${specifier}\``);
      continue;
    }
    const target = resolve(dirname(file), specifier.replace(/\.js$/, '.ts'));
    const name = target.split('/').at(-1) ?? '';
    if (FORBIDDEN_MODULES.includes(name)) {
      failures.push(`${where} -> ${name}: Profile A must not reach ${name}`);
      continue;
    }
    walk(target, [...chain, relative(ROOT, file)]);
  }
}

walk(ENTRY, []);

const reached = [...visited].map((f) => relative(ROOT, f)).sort();
if (failures.length > 0) {
  process.stderr.write(`Profile A dependency isolation FAILED\n${failures.map((f) => `  - ${f}\n`).join('')}`);
  process.exit(1);
}
process.stdout.write(
  `Profile A dependency isolation OK\n  Web Crypto only, ${reached.length} modules reached:\n` +
    reached.map((f) => `    ${f}\n`).join(''),
);
