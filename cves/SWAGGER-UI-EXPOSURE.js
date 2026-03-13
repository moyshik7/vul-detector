/**
 * SWAGGER-UI-EXPOSURE - Exposed API Documentation
 * 
 * This module probes for common Swagger/OpenAPI documentation endpoints 
 * which can leak API structure, parameters, and sensitive endpoints.
 */

module.exports = {
  id: 'SWAGGER-UI-EXPOSURE',
  name: 'Exposed Swagger UI',
  severity: 'MEDIUM',
  description: 'Detects exposed Swagger/OpenAPI documentation which can reveal internal API structures.',
  references: ['https://swagger.io/tools/swagger-ui/'],

  async scan(targetUrl, httpClient) {
    const endpoints = [
      '/swagger-ui.html', 
      '/swagger/index.html', 
      '/api/swagger-ui.html', 
      '/api/docs', 
      '/v2/api-docs', 
      '/v3/api-docs',
      '/swagger.json',
      '/openapi.json'
    ];
    const baseUrl = targetUrl.replace(/\/$/, '');
    const findings = [];

    for (const endpoint of endpoints) {
      try {
        const url = `${baseUrl}${endpoint}`;
        const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
        if (resp.status === 200 && (resp.data.includes('swagger') || resp.data.includes('openapi') || resp.data.includes('Swagger UI'))) {
          findings.push(endpoint);
        }
      } catch (e) {}
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: `Found exposed Swagger/API documentation: ${findings.join(', ')}`,
        evidence: `Endpoints: ${findings.join(', ')}`
      };
    }
    return { vulnerable: false };
  }
};
