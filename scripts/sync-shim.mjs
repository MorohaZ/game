import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { syncHostingConfigs } from './csp-config.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

const pyPath = path.resolve(projectRoot, 'src/bridge/socket_shim.py');
const tsPath = path.resolve(projectRoot, 'src/bridge/python-socket-shim.ts');

if (!fs.existsSync(pyPath)) {
  console.error(`[sync-shim] Error: ${pyPath} does not exist`);
  process.exit(1);
}

const pyCode = fs.readFileSync(pyPath, 'utf-8');
const tsContent = `/**
 * Auto-generated from src/bridge/socket_shim.py
 * DO NOT EDIT DIRECTLY. Edit socket_shim.py and run 'node scripts/sync-shim.mjs'.
 */
export const PYTHON_SOCKET_SHIM_CODE = ${JSON.stringify(pyCode)};
`;

fs.writeFileSync(tsPath, tsContent, 'utf-8');
console.log(`[sync-shim] Successfully synced ${pyPath} -> ${tsPath}`);

syncHostingConfigs(projectRoot);
console.log(`[sync-shim] Successfully synced CSP headers to _headers, public/_headers, netlify.toml, and vercel.json`);

