/**
 * ENV-EXPOSURE - Exposed .env Secrets
 * 
 * This module probes for exposed environment files like .env or .env.local 
 * which often contain API keys, database credentials, and other secrets.
 */

module.exports = {
  id: 'ENV-EXPOSURE',
  name: 'Exposed .env Secrets',
  severity: 'CRITICAL',
  description: 'Detects exposed .env files containing sensitive application secrets and credentials.',
  references: ['https://cwe.mitre.org/data/definitions/522.html'],

  async scan(targetUrl, httpClient) {
    const envFiles = ['.env', '.env.local', '.env.production', '.env.example'];
    const baseUrl = targetUrl.replace(/\/$/, '');
    const findings = [];

    for (const file of envFiles) {
      try {
        const url = `${baseUrl}/${file}`;
        const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
        if (resp.status === 200 && (resp.data.includes('=') || resp.data.includes('API_KEY') || resp.data.includes('DB_'))) {
          findings.push(file);
        }
      } catch (e) {}
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: `Found exposed environment files: ${findings.join(', ')}`,
        evidence: `Files: ${findings.join(', ')}`
      };
    }
    return { vulnerable: false };
  }
};
