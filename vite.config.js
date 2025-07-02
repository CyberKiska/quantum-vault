import { defineConfig } from 'vite';
export default {
  base: '/quantum-vault/',
  optimizeDeps: { include: ['@noble/hashes', '@noble/post-quantum'] }
};
