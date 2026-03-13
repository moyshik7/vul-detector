/**
 * WP-XMLRPC-ENABLED - WordPress XML-RPC Interface Enabled
 * 
 * This module probes for enabled XML-RPC in WordPress 
 * which can be used for amplification-style brute force and pingback attacks.
 */

module.exports = {
  id: 'WP-XMLRPC-ENABLED',
  name: 'WordPress XML-RPC Enabled',
  severity: 'MEDIUM',
  description: 'Detects enabled WordPress XML-RPC which can be used for brute-force and DDoS amplification.',
  references: ['https://codex.wordpress.org/XML-RPC_Support'],

  async scan(targetUrl, httpClient) {
    const url = `${targetUrl.replace(/\/$/, '')}/xmlrpc.php`;
    try {
      const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
      if (resp.status === 200 && (resp.data.includes('XML-RPC server accepts POST requests only'))) {
        return {
          vulnerable: true,
          details: 'WordPress XML-RPC interface is enabled.',
          evidence: `Status: ${resp.status}, Body: ${resp.data.trim()}`
        };
      }
    } catch (e) {}
    return { vulnerable: false };
  }
};
