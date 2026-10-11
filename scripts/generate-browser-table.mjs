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
    console.log(`[generate-browser-table] Artifact ${jsonPath} not found. Gracefully skipping table update.`);
    return true;
  }

  const data = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));
  const rows = [];

  const ciRunner = data.environment?.ciRunner || (data.environment?.isCI ? 'ubuntu-24.04 (GitHub Actions)' : 'CI Runner (ubuntu-24.04)');
  const commitHash = data.commit ? data.commit.substring(0, 7) : 'latest';
  const timestamp = data.timestamp || new Date().toISOString();

  rows.push(`> **Latest CI Run Reference:** [GitHub Actions CI Workflow](https://github.com/MorohaZ/game/actions/workflows/ci.yml) | Run Reference Pattern: \`https://github.com/MorohaZ/game/actions/runs/<run_id>\` | Commit: \`${commitHash}\` | Timestamp: \`${timestamp}\``);
  rows.push('');
  rows.push('| Browser Engine | Target Engine | Environment / Platform | Worker Type | Tests Passed | Status |');
  rows.push('| :--- | :--- | :--- | :--- | :--- | :--- |');

  for (const b of data.browserResults || []) {
    const version = b.browserVersion || 'Detected';
    const total = b.total || 0;
    const passed = b.passed || 0;
    const xfail = b.xfail || 0;
    const status = b.success ? '**PASS**' : '**FAIL**';
    const passRate = total > 0 ? `${passed} / ${total}` : 'N/A';
    const xfailInfo = xfail > 0 ? ` (+${xfail} xfail)` : '';
    const platform = b.browserPath && b.browserPath.includes('ms-playwright')
      ? 'Ubuntu 24.04 (CI Playwright)'
      : (data.environment?.isCI ? 'Ubuntu 24.04 (GitHub Actions)' : 'Playwright / Headless Binary');

    rows.push(
      `| **${b.browser}** | ${version} | ${platform} | ES Module Worker | **${passRate}**${xfailInfo} | ${status} |`
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
