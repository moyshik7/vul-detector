/**
 * Security Headers Check
 *
 * Checks for the presence and proper configuration of critical
 * HTTP security headers that protect against common web attacks.
 */

module.exports = {
  id: 'SEC-HEADERS',
  name: 'Missing Security Headers',
  severity: 'MEDIUM',
  description:
    'Analyzes HTTP response headers for missing or misconfigured security headers that protect against XSS, clickjacking, MIME sniffing, and other attacks.',
  references: [
    'https://owasp.org/www-project-secure-headers/',
    'https://securityheaders.com/',
    'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security',
  ],

  async scan(targetUrl, httpClient) {
    const findings = [];

    try {
      const resp = await httpClient.get(targetUrl);
      const headers = resp.headers;

      // Required security headers and their descriptions
      const requiredHeaders = [
        {
          name: 'Strict-Transport-Security',
          alias: 'HSTS',
          description: 'Enforces HTTPS connections',
          validator: (val) => {
            if (!val) return 'Missing';
            if (!val.includes('max-age')) return 'Missing max-age directive';
            const maxAge = parseInt(val.match(/max-age=(\d+)/)?.[1] || '0');
            if (maxAge < 31536000) return `max-age too short (${maxAge}s, recommend >= 31536000)`;
            return null;
          },
        },
        {
          name: 'Content-Security-Policy',
          alias: 'CSP',
          description: 'Controls resource loading to prevent XSS',
          validator: (val) => {
            if (!val) return 'Missing';
            if (val.includes("'unsafe-inline'")) return "Contains 'unsafe-inline' — weakens XSS protection";
            if (val.includes("'unsafe-eval'")) return "Contains 'unsafe-eval' — allows eval()";
            return null;
          },
        },
        {
          name: 'X-Content-Type-Options',
          alias: 'XCTO',
          description: 'Prevents MIME type sniffing',
          validator: (val) => {
            if (!val) return 'Missing';
            if (val.toLowerCase() !== 'nosniff') return `Invalid value: ${val} (expected 'nosniff')`;
            return null;
          },
        },
        {
          name: 'X-Frame-Options',
          alias: 'XFO',
          description: 'Prevents clickjacking attacks',
          validator: (val) => {
            if (!val) return 'Missing (consider frame-ancestors in CSP)';
            const upper = val.toUpperCase();
            if (!['DENY', 'SAMEORIGIN'].includes(upper)) {
              return `Insecure value: ${val} (use DENY or SAMEORIGIN)`;
            }
            return null;
          },
        },
        {
          name: 'X-XSS-Protection',
          alias: 'XXSS',
          description: 'Legacy XSS protection header',
          validator: (val) => {
            // Modern best practice is to set to 0 and rely on CSP, or 1; mode=block
            if (!val) return 'Missing';
            return null;
          },
        },
        {
          name: 'Referrer-Policy',
          alias: 'RP',
          description: 'Controls referrer information sent with requests',
          validator: (val) => {
            if (!val) return 'Missing';
            const insecureValues = ['unsafe-url', 'no-referrer-when-downgrade'];
            if (insecureValues.includes(val.toLowerCase())) {
              return `Potentially insecure value: ${val}`;
            }
            return null;
          },
        },
        {
          name: 'Permissions-Policy',
          alias: 'PP',
          description: 'Controls browser feature access (camera, microphone, etc.)',
          validator: (val) => {
            if (!val) return 'Missing';
            return null;
          },
        },
      ];

      for (const header of requiredHeaders) {
        const headerValue = headers[header.name.toLowerCase()];
        const issue = header.validator(headerValue);

        if (issue) {
          findings.push(`${header.alias} (${header.name}): ${issue} — ${header.description}`);
        }
      }

      // Check for information disclosure headers
      const infoHeaders = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];
      for (const h of infoHeaders) {
        if (headers[h]) {
          findings.push(`Information disclosure: '${h}: ${headers[h]}' — reveals server technology`);
        }
      }

    } catch (e) {
      return {
        vulnerable: false,
        details: `Could not fetch headers: ${e.message}`,
      };
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: `Found ${findings.length} security header issue(s).`,
        evidence: findings.join('; '),
      };
    }

    return {
      vulnerable: false,
      details: 'All checked security headers are properly configured.',
    };
  },
};
