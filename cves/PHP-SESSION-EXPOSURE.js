/**
 * PHP-SESSION-EXPOSURE - Exposed PHP Session Storage
 * 
 * This module probes for common PHP session storage directories or files 
 * that might be unintentionally exposed to the web.
 * Accessing these can allow session hijacking or information leakage.
 */

module.exports = {
  id: 'PHP-SESSION-EXPOSURE',
  name: 'PHP Session Exposure',
  severity: 'HIGH',
  description: 'Probes for exposed PHP session files or storage directories that could lead to session hijacking.',
  references: [
    'https://www.php.net/manual/en/session.configuration.php#ini.session.save-path',
    'https://cwe.mitre.org/data/definitions/200.html'
  ],

  async scan(targetUrl, httpClient, options = {}) {
    const findings = [];
    const baseUrl = targetUrl.replace(/\/$/, '');

    const sessionPaths = [
      '/var/lib/php/sessions',
      '/tmp/sess_',
      '/sessions/',
      '/session_data/',
      '/php_sessions/'
    ];

    for (const path of sessionPaths) {
      try {
        const url = `${baseUrl}${path}`;
        const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });

        if (resp.status === 200) {
          const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');
          if (body.includes('sess_') || body.includes('size') || body.length > 100) {
            findings.push(`Exposed session storage directory or file at ${path} (HTTP ${resp.status})`);
          }
        }
      } catch (e) {
        // Skip
      }
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: 'Detected indicators of exposed PHP session files or directories.',
        evidence: findings.join('; ')
      };
    }

    return { vulnerable: false, details: 'No exposed PHP sessions detected.' };
  }
};
