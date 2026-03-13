/**
 * WP-VERSION-LEAK - WordPress Version Metadata Disclosure
 * 
 * This module parses the page source for WordPress version metadata 
 * which can help attackers find version-specific vulnerabilities.
 */

const cheerio = require('cheerio');

module.exports = {
  id: 'WP-VERSION-LEAK',
  name: 'WordPress Version Disclosure',
  severity: 'LOW',
  description: 'Detects disclosed WordPress version metadata in page source.',
  references: ['https://cwe.mitre.org/data/definitions/200.html'],

  async scan(targetUrl, httpClient) {
    try {
      const resp = await httpClient.get(targetUrl, { timeout: 5000 });
      const $ = cheerio.load(resp.data);
      const generator = $('meta[name="generator"]').attr('content');

      if (generator && generator.includes('WordPress')) {
        return {
          vulnerable: true,
          details: `Found WordPress version metadata disclosure: ${generator}`,
          evidence: `Tag: <meta name="generator" content="${generator}">`
        };
      }
    } catch (e) {}
    return { vulnerable: false };
  }
};
