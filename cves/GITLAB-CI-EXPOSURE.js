/**
 * GITLAB-CI-EXPOSURE - Exposed GitLab CI/CD Configuration
 * 
 * This module probes for exposed .gitlab-ci.yml files 
 * which disclose build pipelines, runners, and environment variables.
 */

module.exports = {
  id: 'GITLAB-CI-EXPOSURE',
  name: 'Exposed GitLab CI Config',
  severity: 'MEDIUM',
  description: 'Detects exposed GitLab CI/CD configuration files leaking pipeline details.',
  references: ['https://docs.gitlab.com/ee/ci/yaml/'],

  async scan(targetUrl, httpClient) {
    const url = `${targetUrl.replace(/\/$/, '')}/.gitlab-ci.yml`;
    try {
      const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
      if (resp.status === 200 && (resp.data.includes('stages:') || resp.data.includes('script:'))) {
        return {
          vulnerable: true,
          details: 'Found exposed GitLab CI/CD configuration (.gitlab-ci.yml).',
          evidence: `Status: ${resp.status}, Snippet: ${resp.data.slice(0, 100).replace(/\n/g, ' ')}`
        };
      }
    } catch (e) {}
    return { vulnerable: false };
  }
};
