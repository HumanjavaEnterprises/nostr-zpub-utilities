import { build } from 'esbuild';

const result = await build({
  entryPoints: ['src/browser.ts'],
  bundle: true,
  minify: true,
  sourcemap: true,
  format: 'iife',
  globalName: 'NostrZpubUtilities',
  outfile: 'dist/browser/nostr-zpub-utils.min.js',
  target: ['es2020'],
  platform: 'browser',
  define: {
    'process.env.NODE_ENV': '"production"',
    global: 'globalThis',
  },
  metafile: true,
});

const output = Object.entries(result.metafile.outputs)
  .filter(([k]) => k.endsWith('.js'))
  .map(([k, v]) => `${k}: ${(v.bytes / 1024).toFixed(1)}KB`);
console.log('Browser bundle built:', output.join(', '));
