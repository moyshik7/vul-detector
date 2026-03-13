/**
 * DOCKERFILE-EXPOSURE - Exposed Docker Build Configuration
 * 
 * This module probes for exposed Dockerfile files 
 * which can leak build steps, base images, and embedded secrets.
 */

module.exports = {
  id: 'DOCKERFILE-EXPOSURE',
  name: 'Exposed Dockerfile',
  severity: 'MEDIUM',
  description: 'Detects exposed Dockerfile files disclosing build environment and potential secrets.',
  references: ['https://docs.docker.com/engine/reference/builder/'],

  async scan(targetUrl, httpClient) {
    const url = `${targetUrl.replace(/\/$/, '')}/Dockerfile`;
    try {
      const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
      if (resp.status === 200 && (resp.data.includes('FROM ') || resp.data.includes('RUN '))) {
        return {
          vulnerable: true,
          details: 'Found exposed Dockerfile.',
          evidence: `Status: ${resp.status}, Snippet: ${resp.data.slice(0, 100).replace(/\n/g, ' ')}`
        };
      }
    } catch (e) {}
    return { vulnerable: false };
  }
};
