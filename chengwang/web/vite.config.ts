import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'

export default defineConfig({
  plugins: [react()],
  // CI keeps source/node_modules read-only and places all generated state in
  // its private run directory. The candidate serves only the trust entry graph.
  cacheDir: process.env.CHENGWANG_VITE_CACHE_DIR || 'node_modules/.vite',
  build: {
    manifest: true,
    assetsInlineLimit: 0,
    rolldownOptions: {
      input: {
        main: fileURLToPath(new URL('./index.html', import.meta.url)),
        trust: fileURLToPath(new URL('./trust.html', import.meta.url)),
      },
    },
  },
  server: {
    proxy: { '/api': 'http://127.0.0.1:7811' },
  },
})
