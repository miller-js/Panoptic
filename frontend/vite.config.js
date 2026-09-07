import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // Vitest (2.x) bundles its own older Vite that can't load @vitejs/plugin-react
  // v6, so tell esbuild to use the automatic JSX runtime for the test transform.
  // The real build still goes through plugin-react.
  esbuild: {
    jsx: 'automatic',
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/test/setup.js',
    css: false,
  },
})
