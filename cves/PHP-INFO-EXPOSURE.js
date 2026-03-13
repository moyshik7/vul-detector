/**
 * PHP-INFO-EXPOSURE - Exposed phpinfo() Diagnostic Page
 * 
 * This module probes for common filenames that output the phpinfo() diagnostic page.
 * This page discloses extensive server details, PHP configuration, and environment variables.
 */

module.exports = {
  id: 'PHP-INFO-EXPOSURE',
  name: 'PHP Info Exposure',
  severity: 'MEDIUM',
  description: 'Probes for exposed phpinfo() diagnostic pages which disclose sensitive server configuration.',
  references: [
    'https://www.php.net/manual/en/function.phpinfo.php',
    'https://cwe.mitre.org/data/definitions/200.html'
  ],

  async scan(targetUrl, httpClient, options = {}) {
    const findings = [];
    const baseUrl = targetUrl.replace(/\/$/, '');

    const phpinfoPaths = [
      '/phpinfo.php',
      '/info.php',
      '/test.php',
      '/p.php',
      '/php.php',
      '/check.php',
      '/version.php',
      '/i.php'
    ];

    for (const path of phpinfoPaths) {
      try {
        const url = `${baseUrl}${path}`;
        const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });

        if (resp.status === 200) {
          const body = typeof resp.data === 'string' ? resp.data : '';
          
          if (body.includes('phpinfo()') || body.includes('PHP Version') || body.includes('System')) {
            findings.push(`Exposed phpinfo() page at ${path} (HTTP ${resp.status})`);
          }
        }
      } catch (e) {
        // Skip
      }
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: 'Exposed phpinfo() diagnostic page(s) detected.',
        evidence: findings.join('; ')
      };
    }

    return { vulnerable: false, details: 'No exposed phpinfo() page detected.' };
  }
};
