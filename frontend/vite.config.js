import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const apiKey = process.env.WEBAPI_API_KEY || ''

function apiProxy() {
  return {
    target: 'http://127.0.0.1:8000',
    changeOrigin: true,
    rewrite: (path) => path.replace(/^\/api/, ''),
    configure: (proxy) => {
      proxy.on('proxyReq', (proxyReq) => {
        if (apiKey) proxyReq.setHeader('X-API-Key', apiKey)
      })
    },
  }
}

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': apiProxy() },
  },
  preview: {
    port: 3000,
    proxy: { '/api': apiProxy() },
  },
})
