/**
 * WP-ADMIN-EXPOSURE - Exposed WordPress Admin Interface
 * 
 * This module probes for exposed WordPress admin and login pages 
 * which indicate a WordPress installation and provide basic brute-force surfaces.
 */

module.exports = {
  id: 'WP-ADMIN-EXPOSURE',
  name: 'Exposed WordPress Admin',
  severity: 'MEDIUM',
  description: 'Detects exposed WordPress admin and login pages disclosing the CMS type.',
  references: ['https://wordpress.org/documentation/article/brute-force-attacks/'],

  async scan(targetUrl, httpClient) {
    const endpoints = ['/wp-admin/', '/wp-login.php'];
    const baseUrl = targetUrl.replace(/\/$/, '');
    const findings = [];

    for (const endpoint of endpoints) {
      try {
        const url = `${baseUrl}${endpoint}`;
        const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
        if (resp.status === 200 && (resp.data.includes('wp-admin') || resp.data.includes('WordPress'))) {
          findings.push(endpoint);
        }
      } catch (e) {}
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: `Found exposed WordPress admin/login: ${findings.join(', ')}`,
        evidence: `Endpoints: ${findings.join(', ')}`
      };
    }
    return { vulnerable: false };
  }
};
