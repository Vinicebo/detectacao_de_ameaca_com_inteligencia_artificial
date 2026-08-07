import { defineConfig } from 'vitest/config';

// Separado do vite.config.ts: o `defineConfig` do Vite não aceita a chave `test`,
// e juntar os dois obriga a suprimir o erro de tipo.
export default defineConfig({
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
  },
});
