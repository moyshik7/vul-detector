/**
 * PYTHON-DEBUG-EXPOSURE - Exposed Python Framework Debug Mode
 * 
 * This module probes for Flask/Django/FastAPI debug pages 
 * which leak source code, environment variables, and interactive consoles.
 */

module.exports = {
  id: 'PYTHON-DEBUG-EXPOSURE',
  name: 'Exposed Python Debug Mode',
  severity: 'CRITICAL',
  description: 'Detects exposed Python (Flask/Django) debug interfaces which leak source/secrets.',
  references: ['https://flask.palletsprojects.com/en/3.0.x/config/#DEBUG'],

  async scan(targetUrl, httpClient) {
    try {
      // Trigger a 404 or deliberate error to see if a debug page is returned
      const url = `${targetUrl.replace(/\/$/, '')}/nonexistent_debug_test_123`;
      const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false });
      const body = typeof resp.data === 'string' ? resp.data : '';

      if (body.includes('Werkzeug Debugger') || body.includes('Django Debug Toolbar') || body.includes('Traceback (most recent call last)')) {
        return {
          vulnerable: true,
          details: 'Python framework debug mode is enabled and exposed.',
          evidence: `Indicator found in 404/Error response: ${body.slice(0, 100).replace(/\n/g, ' ')}`
        };
      }
    } catch (e) {}
    return { vulnerable: false };
  }
};
