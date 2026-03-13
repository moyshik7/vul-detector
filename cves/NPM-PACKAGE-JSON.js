/**
 * NPM-PACKAGE-JSON - Exposed Node.js Project Manifest
 * 
 * This module probes for exposed package.json files 
 * which disclose dependencies, scripts, and internal project meta-data.
 */

module.exports = {
  id: 'NPM-PACKAGE-JSON',
  name: 'Exposed package.json',
  severity: 'LOW',
  description: 'Detects exposed package.json manifest files disclosing project metadata and dependencies.',
  references: ['https://docs.npmjs.com/cli/v10/configuring-npm/package-json'],

  async scan(targetUrl, httpClient) {
    const url = `${targetUrl.replace(/\/$/, '')}/package.json`;
    try {
      const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
      if (resp.status === 200 && (resp.data.includes('"dependencies"') || resp.data.includes('"name"'))) {
        return {
          vulnerable: true,
          details: 'Found exposed Node.js project manifest (package.json).',
          evidence: `Status: ${resp.status}, Snippet: ${resp.data.slice(0, 100)}`
        };
      }
    } catch (e) {}
    return { vulnerable: false };
  }
};
