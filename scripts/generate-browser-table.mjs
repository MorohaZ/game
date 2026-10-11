import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const jsonPath = path.resolve(projectRoot, 'browser-test-results.json');
const mdPath = path.resolve(projectRoot, 'PHASE_0_ACCEPTANCE_CRITERIA.md');

export function updateBrowserTable() {
  if (!fs.existsSync(jsonPath)) {
    console.warn(`[generate-browser-table] Artifact ${jsonPath} not found.`);
    return false;
  }

  const data = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));
  const rows = [];

  rows.push('| Browser Engine | Browser Version | Binary Path | Worker Type | Tests Passed | Duration | Status |');
  rows.push('| :--- | :--- | :--- | :--- | :--- | :--- | :--- |');

  for (const b of data.browserResults || []) {
    const version = b.browserVersion || 'Detected';
    const total = b.total || 0;
    const passed = b.passed || 0;
    const xfail = b.xfail || 0;
    const status = b.success ? '**PASS**' : '**FAIL**';
    const dur = b.durationMs ? `${b.durationMs} ms` : '-';
    const passRate = total > 0 ? `${passed} / ${total}` : 'N/A';
    const xfailInfo = xfail > 0 ? ` (+${xfail} xfail)` : '';
    rows.push(
      `| **${b.browser}** | ${version} | \`${b.browserPath}\` | ES Module Worker | **${passRate}**${xfailInfo} | ${dur} | ${status} |`
    );
  }

  const tableMarkdown = rows.join('\n');

  if (fs.existsSync(mdPath)) {
    let md = fs.readFileSync(mdPath, 'utf-8');
    const startTag = '<!-- BROWSER_TEST_TABLE_START -->';
    const endTag = '<!-- BROWSER_TEST_TABLE_END -->';

    if (md.includes(startTag) && md.includes(endTag)) {
      const before = md.substring(0, md.indexOf(startTag) + startTag.length);
      const after = md.substring(md.indexOf(endTag));
      const updatedMd = `${before}\n${tableMarkdown}\n${after}`;
      fs.writeFileSync(mdPath, updatedMd, 'utf-8');
      console.log(`[generate-browser-table] Successfully updated table in ${mdPath}`);
      return true;
    } else {
      console.warn(`[generate-browser-table] Tags ${startTag} / ${endTag} not found in ${mdPath}`);
    }
  }

  return false;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  updateBrowserTable();
}
