/**
 * DOCKER-COMPOSE-EXPOSURE - Exposed Infrastructure Configuration
 * 
 * This module probes for exposed docker-compose.yml files 
 * which can leak container setup, environment variables, and network structures.
 */

module.exports = {
  id: 'DOCKER-COMPOSE-EXPOSURE',
  name: 'Exposed Docker Compose Config',
  severity: 'HIGH',
  description: 'Detects exposed docker-compose.yml files which can leak infrastructure and secret details.',
  references: ['https://cwe.mitre.org/data/definitions/200.html'],

  async scan(targetUrl, httpClient) {
    const files = ['docker-compose.yml', 'docker-compose.yaml'];
    const baseUrl = targetUrl.replace(/\/$/, '');
    const findings = [];

    for (const file of files) {
      try {
        const url = `${baseUrl}/${file}`;
        const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
        if (resp.status === 200 && (resp.data.includes('services:') || resp.data.includes('version:'))) {
          findings.push(file);
        }
      } catch (e) {}
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: `Found exposed Docker Compose files: ${findings.join(', ')}`,
        evidence: `Files: ${findings.join(', ')}`
      };
    }
    return { vulnerable: false };
  }
};
