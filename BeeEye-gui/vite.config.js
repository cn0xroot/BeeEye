import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The analyzer UI is served by BeeEye-gui on :8081 in production. In dev the
// Vite server proxies the API through, so the frontend can be reloaded without
// restarting the capture — losing a running capture to a CSS change would be
// an unpleasant way to work.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,
    proxy: {
      '/api': {
        target: process.env.BEEEYE_GUI_API || 'http://localhost:8081',
        changeOrigin: true,
      },
    },
  },
  build: { outDir: 'dist', emptyOutDir: true, chunkSizeWarningLimit: 900 },
})
