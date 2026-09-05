import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/.wrangler/**',
      'vectors/vectors.json',
      'paper/**',
      // Built output of the sandbox PWA; its source is demo/src.
      'demo/pwa/**',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      parserOptions: { projectService: false },
    },
    rules: {
      // A security-critical path should not have escape hatches in it. `any`
      // is banned outright in core by the stricter block below; elsewhere it
      // is a warning so that test scaffolding is not obstructed.
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports' }],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      eqeqeq: ['error', 'always'],
      'no-console': 'error',
      'prefer-const': 'error',
    },
  },
  {
    // The shipped library. No `any`, and no console output: a verification
    // library must never write payload content anywhere.
    files: ['packages/core/src/**/*.ts'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      'no-restricted-globals': [
        'error',
        { name: 'console', message: 'core must never log; payload content must not reach any sink' },
      ],
    },
  },
  {
    // The service worker runs in a worker scope, not a window; the build
    // script substitutes the two placeholders before it is served.
    files: ['demo/src/sw.js'],
    languageOptions: {
      globals: {
        self: 'readonly',
        caches: 'readonly',
        fetch: 'readonly',
        Response: 'readonly',
        URL: 'readonly',
        __PRECACHE__: 'readonly',
      },
    },
  },
  {
    files: ['demo/src/**/*.ts'],
    languageOptions: {
      globals: {
        window: 'readonly', document: 'readonly', navigator: 'readonly', location: 'readonly',
        localStorage: 'readonly', crypto: 'readonly', fetch: 'readonly', performance: 'readonly',
        atob: 'readonly', TextEncoder: 'readonly', Blob: 'readonly', URL: 'readonly', File: 'readonly',
        HTMLElement: 'readonly', HTMLInputElement: 'readonly', HTMLSelectElement: 'readonly',
        HTMLTextAreaElement: 'readonly', HTMLCanvasElement: 'readonly', HTMLVideoElement: 'readonly',
        HTMLButtonElement: 'readonly', MediaStream: 'readonly', JsonWebKey: 'readonly', CryptoKey: 'readonly',
        Event: 'readonly', ImageBitmapSource: 'readonly', createImageBitmap: 'readonly',
      },
    },
  },
  {
    // The end-to-end check runs under Node and drives a browser; it reports
    // through process.stdout like the CLI does.
    files: ['demo/e2e/**/*.mjs'],
    languageOptions: {
      // `document` appears inside page.evaluate callbacks, which run in the browser.
      globals: { process: 'readonly', Buffer: 'readonly', setTimeout: 'readonly', document: 'readonly' },
    },
  },
  {
    files: ['packages/cli/src/**/*.ts', 'tools/**/*.ts'],
    rules: {
      // The CLI and the tools write to stdout and stderr by design, through
      // process streams rather than console.
      'no-console': 'error',
    },
  },
);
