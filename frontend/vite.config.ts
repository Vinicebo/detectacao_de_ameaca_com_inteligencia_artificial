import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const API_URL = process.env.API_URL ?? 'http://localhost:46970';

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    // Em dev o Vite serve na 5173 e faz proxy do /api para a API, então o
    // frontend usa caminhos relativos e não precisa saber a URL do backend.
    // Em produção quem faz esse proxy é o nginx (ver frontend/nginx.conf).
    proxy: {
      '/api': {
        target: API_URL,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
      '/ws': {
        target: API_URL,
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
