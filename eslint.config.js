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
    files: ['packages/cli/src/**/*.ts', 'tools/**/*.ts'],
    rules: {
      // The CLI and the tools write to stdout and stderr by design, through
      // process streams rather than console.
      'no-console': 'error',
    },
  },
);
