/**
 * DIRECTORY-LISTING - Directory Indexing Enabled
 * 
 * This module probes for enabled directory listing, 
 * which allows attackers to browse the files on the server.
 */

module.exports = {
  id: 'DIRECTORY-LISTING',
  name: 'Directory Listing Enabled',
  severity: 'MEDIUM',
  description: 'Detects enabled directory listing which reveals server file structure.',
  references: ['https://cwe.mitre.org/data/definitions/548.html'],

  async scan(targetUrl, httpClient) {
    const paths = ['/', '/images/', '/img/', '/uploads/', '/js/', '/css/', '/static/'];
    const baseUrl = targetUrl.replace(/\/$/, '');
    const findings = [];

    for (const path of paths) {
      try {
        const url = `${baseUrl}${path}`;
        const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
        if (resp.status === 200 && (resp.data.includes('Index of /') || resp.data.includes('<title>Index of'))) {
          findings.push(path);
        }
      } catch (e) {}
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: `Directory listing enabled at: ${findings.join(', ')}`,
        evidence: `Paths: ${findings.join(', ')}`
      };
    }
    return { vulnerable: false };
  }
};
