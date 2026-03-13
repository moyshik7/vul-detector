/**
 * GRAPHQL-INTROSPECTION - GraphQL Introspection Enabled
 * 
 * This module probes for enabled GraphQL introspection, 
 * which allows attackers to explore the entire API schema.
 */

module.exports = {
  id: 'GRAPHQL-INTROSPECTION',
  name: 'GraphQL Introspection Enabled',
  severity: 'MEDIUM',
  description: 'Detects enabled GraphQL introspection which allows the entire API schema to be queried.',
  references: ['https://graphql.org/learn/introspection/'],

  async scan(targetUrl, httpClient) {
    const endpoints = ['/graphql', '/api/graphql', '/v1/graphql'];
    const introspectionQuery = {
      query: '{ __schema { types { name } } }'
    };
    const baseUrl = targetUrl.replace(/\/$/, '');
    const findings = [];

    for (const endpoint of endpoints) {
      try {
        const url = `${baseUrl}${endpoint}`;
        const resp = await httpClient.post(url, introspectionQuery, { 
          timeout: 5000, 
          headers: { 'Content-Type': 'application/json' },
          validateStatus: false 
        });
        if (resp.status === 200 && resp.data && resp.data.data && resp.data.data.__schema) {
          findings.push(endpoint);
        }
      } catch (e) {}
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: `GraphQL Introspection enabled at: ${findings.join(', ')}`,
        evidence: `Endpoints: ${findings.join(', ')}`
      };
    }
    return { vulnerable: false };
  }
};
