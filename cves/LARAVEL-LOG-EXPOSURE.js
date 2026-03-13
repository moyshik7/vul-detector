/**
 * LARAVEL-LOG-EXPOSURE - Exposed Laravel Framework Logs
 * 
 * This module probes for exposed Laravel application logs 
 * which can contain sensitive stack traces, queries, and secret values.
 */

module.exports = {
  id: 'LARAVEL-LOG-EXPOSURE',
  name: 'Exposed Laravel Logs',
  severity: 'HIGH',
  description: 'Detects exposed Laravel framework logs which can disclose sensitive application traces.',
  references: ['https://cwe.mitre.org/data/definitions/200.html'],

  async scan(targetUrl, httpClient) {
    const url = `${targetUrl.replace(/\/$/, '')}/storage/logs/laravel.log`;
    try {
      const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
      if (resp.status === 200 && (resp.data.includes('laravel.ERROR') || resp.data.includes('local.INFO'))) {
        return {
          vulnerable: true,
          details: 'Found exposed Laravel application log (laravel.log).',
          evidence: `Status: ${resp.status}, Snippet: ${resp.data.slice(0, 150).replace(/\n/g, ' ')}`
        };
      }
    } catch (e) {}
    return { vulnerable: false };
  }
};
