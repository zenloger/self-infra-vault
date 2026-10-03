import { build } from 'esbuild';
import { mkdir, copyFile, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
await mkdir(resolve(root, 'dist'), { recursive: true });
const result = await build({
  absWorkingDir: root,
  entryPoints: { app: 'client/app.js', 'vault-worker': 'client/vault-worker.js' },
  outdir: 'dist',
  bundle: true,
  platform: 'browser',
  format: 'esm',
  target: ['es2022'],
  // Build the original TS sources so pinned XML/fflate overrides really apply:
  // the upstream UMD distribution contains its own older bundled fflate.
  alias: { kdbxweb: resolve(root, 'node_modules/kdbxweb/lib/index.ts') },
  define: { global: 'globalThis' },
  minify: true,
  sourcemap: false,
  legalComments: 'linked',
  metafile: true,
  plugins: [{
    name: 'native-webcrypto-only',
    setup(builder) {
      // KdbxWeb's source imports Node crypto even when native WebCrypto is
      // available. Browser workers use crypto.subtle; never bundle a fallback.
      builder.onResolve({ filter: /^crypto$/ }, () => ({ path: 'crypto', namespace: 'webcrypto' }));
      builder.onLoad({ filter: /.*/, namespace: 'webcrypto' }, () => ({ contents: 'module.exports = {};', loader: 'js' }));
    },
  }],
});
for (const name of ['index.html', 'style.css']) await copyFile(resolve(root, 'client', name), resolve(root, 'dist', name));
const licenses = [];
const resolveDependency = createRequire(resolve(root, 'node_modules/kdbxweb/package.json'));
for (const [name, filename] of [['kdbxweb', 'LICENSE'], ['hash-wasm', 'LICENSE'], ['@xmldom/xmldom', 'LICENSE'], ['fflate', 'LICENSE']]) {
  const directory = dirname(resolveDependency.resolve(`${name}/package.json`));
  licenses.push(`${name}\n${'='.repeat(name.length)}\n${await readFile(resolve(directory, filename), 'utf8')}`);
}
await writeFile(resolve(root, 'dist/third-party-licenses.txt'), licenses.join('\n\n'));
await writeFile(resolve(root, 'build-meta.json'), JSON.stringify(result.metafile, null, 2) + '\n');
for (const [name, output] of Object.entries(result.metafile.outputs)) console.log(`${name}: ${output.bytes} bytes`);
