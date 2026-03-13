/**
 * SENSITIVE-LOGS - Exposed Sensitive Log Files
 * 
 * This module probes for common log file locations 
 * which can disclose sensitive information, errors, and system details.
 */

module.exports = {
  id: 'SENSITIVE-LOGS',
  name: 'Exposed Sensitive Log Files',
  severity: 'MEDIUM',
  description: 'Detects exposed log files which can disclose sensitive system and application errors.',
  references: ['https://cwe.mitre.org/data/definitions/200.html'],

  async scan(targetUrl, httpClient) {
    const files = [
      'error.log', 
      'access.log', 
      'npm-debug.log', 
      'yarn-error.log', 
      'server.log', 
      'debug.log'
    ];
    const baseUrl = targetUrl.replace(/\/$/, '');
    const findings = [];

    for (const file of files) {
      try {
        const url = `${baseUrl}/${file}`;
        const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
        if (resp.status === 200 && (resp.data.includes('[error]') || resp.data.includes('GET ') || resp.data.includes('POST '))) {
          findings.push(file);
        }
      } catch (e) {}
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: `Found exposed log files: ${findings.join(', ')}`,
        evidence: `Files: ${findings.join(', ')}`
      };
    }
    return { vulnerable: false };
  }
};
