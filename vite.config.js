import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 3000, // Frontend runs on http://localhost:3000
    proxy: {
      '/api': {
        target: 'https://oak-dental.onrender.com', // Backend URL
        changeOrigin: true, // Changes the origin of the host header to the target URL
        secure: false // Allows proxying to an HTTPS backend without certificate validation (for development)
      }
    }
  },
  root: 'public' // Serve files from the public directory
});