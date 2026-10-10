import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

const pyodideSrcDir = path.resolve(projectRoot, 'node_modules/pyodide');
const publicPyodideDir = path.resolve(projectRoot, 'public/pyodide');
const distPyodideDir = path.resolve(projectRoot, 'dist/pyodide');

const filesToCopy = [
  'pyodide.asm.js',
  'pyodide.asm.wasm',
  'pyodide.js',
  'pyodide.mjs',
  'python_stdlib.zip',
  'pyodide-lock.json',
];

if (!fs.existsSync(pyodideSrcDir)) {
  console.error(`[copy-pyodide] Source directory not found: ${pyodideSrcDir}`);
  process.exit(1);
}

fs.mkdirSync(publicPyodideDir, { recursive: true });

for (const file of filesToCopy) {
  const src = path.join(pyodideSrcDir, file);
  const destPublic = path.join(publicPyodideDir, file);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, destPublic);
  } else {
    console.warn(`[copy-pyodide] Warning: ${src} not found`);
  }
}

// Also copy to dist/pyodide if dist exists
if (fs.existsSync(path.resolve(projectRoot, 'dist'))) {
  fs.mkdirSync(distPyodideDir, { recursive: true });
  for (const file of filesToCopy) {
    const src = path.join(pyodideSrcDir, file);
    const destDist = path.join(distPyodideDir, file);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, destDist);
    }
  }
}

console.log(`[copy-pyodide] Successfully copied Pyodide assets to ${publicPyodideDir}`);
