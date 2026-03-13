/**
 * GENERIC-OPEN-REDIRECT - Common Open Redirect Vector
 * 
 * This module probes for open redirect vulnerabilities via common 
 * URI parameters frequently misused for phishing.
 */

module.exports = {
  id: 'GENERIC-OPEN-REDIRECT',
  name: 'Open Redirect Vulnerability',
  severity: 'MEDIUM',
  description: 'Detects open redirect vulnerabilities via common URL parameters.',
  references: ['https://cwe.mitre.org/data/definitions/601.html'],

  async scan(targetUrl, httpClient) {
    const params = ['url', 'redirect', 'next', 'dest', 'destination', 'out', 'view', 'to'];
    const redirectTarget = 'https://example.com/vulscan_redirect_test';
    const baseUrl = targetUrl.replace(/\/$/, '');
    const findings = [];

    for (const param of params) {
      try {
        const url = `${baseUrl}?${param}=${encodeURIComponent(redirectTarget)}`;
        const resp = await httpClient.get(url, { timeout: 5000, maxRedirects: 0, validateStatus: false });
        
        const location = resp.headers['location'] || '';
        if ((resp.status >= 300 && resp.status < 400) && location.includes(redirectTarget)) {
          findings.push(`${param} (Location: ${location})`);
        }
      } catch (e) {}
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: `Open redirect detected via: ${findings.join(', ')}`,
        evidence: `Findings: ${findings.join(', ')}`
      };
    }
    return { vulnerable: false };
  }
};
