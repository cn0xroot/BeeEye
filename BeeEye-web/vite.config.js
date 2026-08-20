import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Served by BeeEye-agent on :8080 in production; proxied in dev.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.BEEEYE_API || 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  build: { outDir: 'dist', emptyOutDir: true },
})
