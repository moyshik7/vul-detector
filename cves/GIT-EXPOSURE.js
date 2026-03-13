/**
 * GIT-EXPOSURE - Exposed .git Directory
 * 
 * This module probes for exposed .git/config files which can disclose 
 * source code, repository structure, and sensitive credentials.
 */

module.exports = {
  id: 'GIT-EXPOSURE',
  name: 'Exposed .git Directory',
  severity: 'HIGH',
  description: 'Detects exposed .git/config which can leak source code and internal repository details.',
  references: ['https://cwe.mitre.org/data/definitions/200.html'],

  async scan(targetUrl, httpClient) {
    const url = `${targetUrl.replace(/\/$/, '')}/.git/config`;
    try {
      const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
      if (resp.status === 200 && (resp.data.includes('[core]') || resp.data.includes('[remote "origin"]'))) {
        return {
          vulnerable: true,
          details: 'Found exposed .git/config file.',
          evidence: `Status: ${resp.status}, Snippet: ${resp.data.slice(0, 100)}`
        };
      }
    } catch (e) {}
    return { vulnerable: false };
  }
};
