// Bundles src/ into a single self-contained ynotes.html (no CDN, works from file:// too).
import { build } from 'esbuild';
import { readFileSync, writeFileSync } from 'node:fs';

const res = await build({
  entryPoints: ['src/app.js'],
  bundle: true,
  minify: true,
  format: 'iife',
  platform: 'browser',
  target: 'es2020',
  write: false,
});
const js = res.outputFiles[0].text.replace(/<\/script/gi, '<\\/script');
const html = readFileSync('src/index.html', 'utf8').replace('<script>/*APP*/</script>', () => `<script>${js}</script>`);
writeFileSync('ynotes.html', html);
console.log(`ynotes.html: ${(html.length / 1024).toFixed(0)} KB`);
