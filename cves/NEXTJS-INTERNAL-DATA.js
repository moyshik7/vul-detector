/**
 * NEXTJS-INTERNAL-DATA - Next.js Information Disclosure in __NEXT_DATA__
 * 
 * This module parses the __NEXT_DATA__ script tag in the page source 
 * to find API keys, secret tokens, or sensitive user data leaked into the client state.
 */

const cheerio = require('cheerio');

module.exports = {
  id: 'NEXTJS-INTERNAL-DATA',
  name: 'Next.js Information Disclosure in __NEXT_DATA__',
  severity: 'HIGH',
  description: 'Probes for sensitive information published into the client-side __NEXT_DATA__ script tag.',
  references: [
    'https://nextjs.org/docs/pages/building-your-application/data-fetching/get-server-side-props',
    'https://cwe.mitre.org/data/definitions/200.html'
  ],

  async scan(targetUrl, httpClient, options = {}) {
    const findings = [];
    
    try {
      const resp = await httpClient.get(targetUrl, { timeout: 5000 });
      const $ = cheerio.load(resp.data);
      const nextData = $('#__NEXT_DATA__').html();

      if (nextData) {
        try {
          const parsedData = JSON.parse(nextData);
          const props = parsedData.props || {};
          const query = parsedData.query || {};

          // Recursive check for sensitive keys
          const sensitiveKeys = ['apiKey', 'secret', 'password', 'token', 'access_token', 'db_', 'database', 'env'];
          
          function checkObject(obj, path = 'props') {
            if (!obj || typeof obj !== 'object') return;
            for (const key in obj) {
              const currentPath = `${path}.${key}`;
              if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
                findings.push(`Sensitive key '${key}' found in __NEXT_DATA__ at ${currentPath}`);
              }
              if (typeof obj[key] === 'object') {
                checkObject(obj[key], currentPath);
              }
            }
          }

          checkObject(props);
          checkObject(query, 'query');
        } catch (e) {
          // JSON parse failed
        }
      }
    } catch (e) {
      // Skip
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: 'Sensitive internal data or environment variables leaked in client-side __NEXT_DATA__ state.',
        evidence: findings.join('; ')
      };
    }

    return { vulnerable: false, details: 'No sensitive data found in __NEXT_DATA__.' };
  }
};
