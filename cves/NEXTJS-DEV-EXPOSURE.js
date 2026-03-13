/**
 * NEXTJS-DEV-EXPOSURE - Exposed Next.js Development and Telemetry Endpoints
 * 
 * This module probes for Next.js internal endpoints that should not be exposed in production.
 * This includes development-only tools and telemetry data.
 */

module.exports = {
  id: 'NEXTJS-DEV-EXPOSURE',
  name: 'Next.js Development/Telemetry Exposure',
  severity: 'MEDIUM',
  description: 'Probes for exposed Next.js internal development and telemetry endpoints in production.',
  references: [
    'https://nextjs.org/docs/app/api-reference/next-config-js/telemetry'
  ],

  async scan(targetUrl, httpClient, options = {}) {
    const findings = [];
    const baseUrl = targetUrl.replace(/\/$/, '');

    const devEndpoints = [
      '/_next/development',
      '/_next/webpack-hmr',
      '/_next/telemetry',
      '/_next/static/development/_devPagesManifest.json',
      '/_next/static/development/_devMiddlewareManifest.json'
    ];

    for (const endpoint of devEndpoints) {
      try {
        const url = `${baseUrl}${endpoint}`;
        const resp = await httpClient.get(url, {
          timeout: 5000,
          validateStatus: false,
          headers: endpoint.includes('hmr') ? { 'Accept': 'text/event-stream' } : {}
        });

        if (resp.status === 200) {
          findings.push(`Exposed internal endpoint: ${endpoint} (HTTP ${resp.status})`);
        }
      } catch (e) {
        // Skip
      }
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: 'Next.js development or telemetry endpoints exposed in production environment.',
        evidence: findings.join('; ')
      };
    }

    return { vulnerable: false, details: 'No exposed Next.js development endpoints detected.' };
  }
};
