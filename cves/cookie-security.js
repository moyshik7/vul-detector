/**
 * Cookie Security Check
 *
 * Analyzes Set-Cookie headers for missing security flags
 * such as HttpOnly, Secure, and SameSite.
 */

module.exports = {
  id: 'SEC-COOKIES',
  name: 'Insecure Cookie Configuration',
  severity: 'MEDIUM',
  description:
    'Checks Set-Cookie headers for missing HttpOnly, Secure, and SameSite attributes that protect against XSS, session hijacking, and CSRF.',
  references: [
    'https://owasp.org/www-community/controls/SecureCookieAttribute',
    'https://cwe.mitre.org/data/definitions/614.html',
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security',
  ],

  async scan(targetUrl, httpClient) {
    const findings = [];

    try {
      const resp = await httpClient.get(targetUrl);

      // Get Set-Cookie headers (can be string or array)
      let cookies = resp.headers['set-cookie'];
      if (!cookies) {
        return {
          vulnerable: false,
          details: 'No Set-Cookie headers present in response.',
        };
      }

      if (!Array.isArray(cookies)) {
        cookies = [cookies];
      }

      for (const cookie of cookies) {
        const cookieName = cookie.split('=')[0].trim();
        const lower = cookie.toLowerCase();

        const issues = [];

        // Check for HttpOnly flag
        if (!lower.includes('httponly')) {
          issues.push('missing HttpOnly');
        }

        // Check for Secure flag
        if (!lower.includes('secure')) {
          issues.push('missing Secure');
        }

        // Check for SameSite flag
        if (!lower.includes('samesite')) {
          issues.push('missing SameSite');
        } else if (lower.includes('samesite=none') && !lower.includes('secure')) {
          issues.push('SameSite=None without Secure flag');
        }

        // Check if session-like cookies have short/no expiry
        const sessionCookieNames = ['session', 'sid', 'sess', 'token', 'auth', 'jwt', 'phpsessid', 'jsessionid', 'asp.net_sessionid'];
        const isSessionCookie = sessionCookieNames.some((s) =>
          cookieName.toLowerCase().includes(s)
        );

        if (isSessionCookie && issues.length > 0) {
          // Session cookies with security issues are more severe
          findings.push(
            `Session cookie '${cookieName}': ${issues.join(', ')} — HIGH RISK for session hijacking`
          );
        } else if (issues.length > 0) {
          findings.push(`Cookie '${cookieName}': ${issues.join(', ')}`);
        }
      }
    } catch (e) {
      return {
        vulnerable: false,
        details: `Could not check cookies: ${e.message}`,
      };
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: `Found ${findings.length} cookie security issue(s).`,
        evidence: findings.join('; '),
      };
    }

    return {
      vulnerable: false,
      details: 'All cookies have proper security attributes (HttpOnly, Secure, SameSite).',
    };
  },
};
