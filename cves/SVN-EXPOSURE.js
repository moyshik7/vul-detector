/**
 * SVN-EXPOSURE - Exposed .svn Directory
 * 
 * This module probes for exposed .svn/entries files which can disclose 
 * source code and internal repository details for SVN-based projects.
 */

module.exports = {
  id: 'SVN-EXPOSURE',
  name: 'Exposed .svn Directory',
  severity: 'HIGH',
  description: 'Detects exposed .svn/entries which can leak source code and internal repository structure.',
  references: ['https://cwe.mitre.org/data/definitions/200.html'],

  async scan(targetUrl, httpClient) {
    const url = `${targetUrl.replace(/\/$/, '')}/.svn/entries`;
    try {
      const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
      if (resp.status === 200 && (resp.data.includes('dir') || resp.data.includes('svn'))) {
        return {
          vulnerable: true,
          details: 'Found exposed .svn/entries file.',
          evidence: `Status: ${resp.status}, Snippet: ${resp.data.slice(0, 100).replace(/\n/g, ' ')}`
        };
      }
    } catch (e) {}
    return { vulnerable: false };
  }
};
