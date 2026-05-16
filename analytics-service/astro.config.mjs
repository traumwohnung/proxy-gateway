import { defineConfig } from 'astro/config';
import node from '@astrojs/node';
import react from '@astrojs/react';
import tailwind from '@tailwindcss/vite';

// Tailwind v4 is wired in as a Vite plugin (the old @astrojs/tailwind
// integration was for v3). Theme tokens live in src/web/styles/globals.css.
export default defineConfig({
  output: 'server',
  adapter: node({ mode: 'middleware' }),
  integrations: [react()],
  vite: { plugins: [tailwind()] },
  srcDir: './src/web',
  server: { host: '127.0.0.1' },
});
