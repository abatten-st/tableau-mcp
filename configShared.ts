import { defineConfig } from 'vitest/config.js';

export const configShared = {
  test: {
    globals: true,
    watch: false,
    // Vitest 4 keeps automock call history across tests unless it is cleared.
    clearMocks: true,
    include: ['**/*.test.ts'],
    reporters: [
      [
        'default',
        {
          summary: false,
        },
      ],
      'junit',
    ],
  },
} satisfies Parameters<typeof defineConfig>[0];
