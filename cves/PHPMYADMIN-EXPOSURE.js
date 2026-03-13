/**
 * PHPMYADMIN-EXPOSURE - Exposed phpMyAdmin Interface
 * 
 * This module probes for exposed phpMyAdmin login pages 
 * which can lead to database brute-forcing or unauthorized access.
 */

module.exports = {
  id: 'PHPMYADMIN-EXPOSURE',
  name: 'Exposed phpMyAdmin',
  severity: 'HIGH',
  description: 'Detects exposed phpMyAdmin login pages which indicate database management accessibility.',
  references: ['https://www.phpmyadmin.net/'],

  async scan(targetUrl, httpClient) {
    const endpoints = [
      '/phpmyadmin/', 
      '/pma/', 
      '/myadmin/', 
      '/dbadmin/', 
      '/mysql/', 
      '/sql/'
    ];
    const baseUrl = targetUrl.replace(/\/$/, '');
    const findings = [];

    for (const endpoint of endpoints) {
      try {
        const url = `${baseUrl}${endpoint}`;
        const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
        if (resp.status === 200 && (resp.data.includes('phpMyAdmin') || resp.data.includes('pma_password'))) {
          findings.push(endpoint);
        }
      } catch (e) {}
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: `Found exposed phpMyAdmin at: ${findings.join(', ')}`,
        evidence: `Endpoints: ${findings.join(', ')}`
      };
    }
    return { vulnerable: false };
  }
};
