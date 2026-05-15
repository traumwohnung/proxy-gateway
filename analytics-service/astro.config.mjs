import { defineConfig } from 'astro/config';
import node from '@astrojs/node';
import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  output: 'server',
  adapter: node({ mode: 'middleware' }),
  integrations: [react(), tailwind({ applyBaseStyles: false })],
  srcDir: './src/web',
  server: { host: '127.0.0.1' },
});
