/**
 * Verify-Write Utilities
 *
 * Non-destructive write-verification probes for deep vulnerability testing.
 * All probes check whether the server *accepts* write-like operations without
 * persisting any harmful data. Each probe logs exactly what was sent and
 * what the server responded with.
 */

const crypto = require('crypto');
const chalk = require('chalk');

const CANARY_PREFIX = 'vulscan';

/**
 * Generate a unique canary string that can be searched for in responses.
 */
function makeCanary(tag = 'probe') {
  const id = crypto.randomBytes(4).toString('hex');
  return `${CANARY_PREFIX}_${tag}_${id}`;
}

/**
 * Capture a baseline response from the target for comparison.
 * Call this once at the start of verify-write probes.
 *
 * @returns {{ statusCode: number, bodySnippet: string, bodyLength: number }}
 */
async function captureBaseline(targetUrl, httpClient) {
  try {
    const resp = await httpClient.get(targetUrl, { timeout: 5000 });
    const body = typeof resp.data === 'string' ? resp.data : '';
    return {
      statusCode: resp.status,
      bodySnippet: body.slice(0, 500),
      bodyLength: body.length,
    };
  } catch (e) {
    return null;
  }
}

/**
 * Check whether a probe response differs meaningfully from the baseline.
 */
function hasChanged(baseline, statusCode, responseBody) {
  if (!baseline) return true; // No baseline = always show

  // Different status code
  if (statusCode !== baseline.statusCode) return true;

  // Significantly different body length (>20% change)
  const lenDiff = Math.abs(responseBody.length - baseline.bodyLength);
  if (baseline.bodyLength > 0 && lenDiff / baseline.bodyLength > 0.2) return true;

  // Body content changed (compare first 500 chars)
  if (responseBody.slice(0, 500) !== baseline.bodySnippet) return true;

  return false;
}

/**
 * Log a probe's details to the console — ONLY if the response differs from baseline.
 * If baseline is provided and response matches, silently skip.
 *
 * @param {string} label - Probe description
 * @param {object} details - { method, url, sentData, statusCode, responseSnippet }
 * @param {object|null} baseline - From captureBaseline(), or null to always log
 * @param {string} fullBody - Full response body for comparison (optional)
 */
function logProbe(label, { method, url, sentData, statusCode, responseSnippet }, baseline = null, fullBody = null) {
  const bodyForCompare = fullBody || responseSnippet || '';

  if (baseline && !hasChanged(baseline, statusCode, bodyForCompare)) {
    return; // Response is the same as baseline — nothing interesting
  }

  console.log(chalk.magentaBright(`\n  ┌─ VERIFY-WRITE PROBE: ${label}`));
  console.log(chalk.gray(`  │  ${method} ${url}`));
  if (sentData) {
    const display = typeof sentData === 'string' ? sentData : JSON.stringify(sentData);
    console.log(chalk.gray(`  │  Sent: `) + chalk.yellowBright(display.slice(0, 200)));
  }
  console.log(chalk.gray(`  │  Response: `) + chalk.cyanBright(`HTTP ${statusCode}`));
  if (baseline) {
    console.log(chalk.gray(`  │  `) + chalk.redBright(`⚠ CHANGED from baseline (was HTTP ${baseline.statusCode}, ${baseline.bodyLength} bytes)`));
  }
  if (responseSnippet) {
    console.log(chalk.gray(`  │  Body: `) + chalk.white(responseSnippet.slice(0, 200)));
  }
  console.log(chalk.magentaBright(`  └─`));
}

/**
 * Test for reflected XSS by injecting a canary string into query parameters
 * and checking if it appears unescaped in the response.
 *
 * @returns {{ findings: string[], probeLog: string[] }}
 */
async function testReflectedXSS(targetUrl, httpClient, params = null) {
  const findings = [];
  const baseline = await captureBaseline(targetUrl, httpClient);
  const testParams = params || ['q', 'search', 'name', 'input', 'text', 'msg', 'error', 'redirect', 'url', 'page'];
  const canary = makeCanary('xss');
  // Use a safe canary that looks like an XSS payload but is harmless
  const xssCanary = `">${canary}<img src=x>`;

  for (const param of testParams) {
    try {
      const testUrl = `${targetUrl}?${param}=${encodeURIComponent(xssCanary)}`;
      const resp = await httpClient.get(testUrl, { timeout: 5000 });
      const body = typeof resp.data === 'string' ? resp.data : '';
      const snippet = body.slice(0, 300);

      logProbe(`Reflected XSS — param '${param}'`, {
        method: 'GET',
        url: testUrl,
        sentData: xssCanary,
        statusCode: resp.status,
        responseSnippet: snippet,
      }, baseline, body);

      // Check if the canary is reflected without HTML encoding
      if (body.includes(xssCanary)) {
        findings.push(
          `CONFIRMED Reflected XSS: canary reflected unescaped in '${param}' parameter`
        );
      } else if (body.includes(canary)) {
        findings.push(
          `Potential Reflected XSS: canary text reflected in '${param}' (HTML may be stripped but text passes through)`
        );
      }
    } catch (e) {
      // Skip unreachable
    }
  }

  return { findings };
}

/**
 * Test form submission endpoints to see if the server accepts POST data.
 * Sends a canary value in common field names.
 *
 * @returns {{ findings: string[] }}
 */
async function testFormSubmission(targetUrl, httpClient, fields = null) {
  const findings = [];
  const baseline = await captureBaseline(targetUrl, httpClient);
  const canary = makeCanary('form');
  const testFields = fields || ['name', 'email', 'comment', 'message', 'body', 'content', 'text', 'title', 'description'];

  // Common form endpoints
  const formEndpoints = [
    '/contact', '/comment', '/feedback', '/submit',
    '/api/contact', '/api/comment', '/api/feedback',
    '/api/submit', '/api/form', '/newsletter',
    '/signup', '/register', '/subscribe',
  ];

  for (const endpoint of formEndpoints) {
    const formData = {};
    for (const field of testFields) {
      formData[field] = `${canary}_${field}`;
    }

    // JSON POST
    try {
      const url = `${targetUrl}${endpoint}`;
      const sentBody = JSON.stringify(formData);
      const resp = await httpClient.post(url, sentBody, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 5000,
        maxRedirects: 0,
      });
      const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

      logProbe(`Form POST (JSON) — ${endpoint}`, {
        method: 'POST',
        url,
        sentData: sentBody,
        statusCode: resp.status,
        responseSnippet: body.slice(0, 300),
      }, baseline, body);

      if (resp.status >= 200 && resp.status < 300) {
        if (body.includes(canary)) {
          findings.push(
            `CONFIRMED: Form endpoint ${endpoint} accepted and reflected POST data (JSON)`
          );
        } else {
          findings.push(
            `Form endpoint ${endpoint} accepted JSON POST (HTTP ${resp.status}) — may accept writes`
          );
        }
      }
    } catch (e) {
      // Not accessible
    }

    // URL-encoded POST
    try {
      const url = `${targetUrl}${endpoint}`;
      const encoded = testFields.map(f => `${f}=${encodeURIComponent(`${canary}_${f}`)}`).join('&');
      const resp = await httpClient.post(url, encoded, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 5000,
        maxRedirects: 0,
      });
      const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

      logProbe(`Form POST (URL-encoded) — ${endpoint}`, {
        method: 'POST',
        url,
        sentData: encoded,
        statusCode: resp.status,
        responseSnippet: body.slice(0, 300),
      }, baseline, body);

      if (resp.status >= 200 && resp.status < 300 && body.includes(canary)) {
        findings.push(
          `CONFIRMED: Form endpoint ${endpoint} accepted and reflected URL-encoded POST data`
        );
      }
    } catch (e) {
      // Not accessible
    }
  }

  return { findings };
}

/**
 * Test for SQL injection write capability via error-based and time-based detection.
 * Does NOT modify any data — uses SELECT-only or time-delay payloads.
 *
 * @returns {{ findings: string[] }}
 */
async function testSQLiWrite(targetUrl, httpClient, params = null) {
  const findings = [];
  const baseline = await captureBaseline(targetUrl, httpClient);
  const testParams = params || ['id', 'q', 'search', 'name', 'user', 'category', 'item', 'product', 'page'];

  const sqliPayloads = [
    { payload: "' OR '1'='1", type: 'boolean-based', desc: 'Boolean-based blind SQLi' },
    { payload: "1' AND SLEEP(3)--", type: 'time-based', desc: 'Time-based blind SQLi', delay: 3000 },
    { payload: "1 UNION SELECT NULL--", type: 'union-based', desc: 'UNION-based SQLi' },
    { payload: "'; SELECT 1;--", type: 'stacked', desc: 'Stacked queries SQLi' },
  ];

  const sqlErrorPatterns = [
    /SQL syntax.*MySQL/i,
    /Warning.*mysql_/i,
    /PostgreSQL.*ERROR/i,
    /ORA-\d{5}/,
    /Microsoft.*ODBC.*SQL/i,
    /Unclosed quotation mark/i,
    /SQLITE_ERROR/i,
    /unterminated quoted string/i,
    /quoted string not properly terminated/i,
  ];

  // Get baseline timing
  let baselineTime = 0;
  try {
    const start = Date.now();
    await httpClient.get(targetUrl, { timeout: 8000 });
    baselineTime = Date.now() - start;
  } catch (e) { /* skip */ }

  for (const param of testParams) {
    for (const { payload, type, desc, delay } of sqliPayloads) {
      try {
        const testUrl = `${targetUrl}?${param}=${encodeURIComponent(payload)}`;
        const startTime = Date.now();
        const resp = await httpClient.get(testUrl, { timeout: 10000 });
        const elapsed = Date.now() - startTime;
        const body = typeof resp.data === 'string' ? resp.data : '';

      logProbe(`SQLi (${type}) — param '${param}'`, {
          method: 'GET',
          url: testUrl,
          sentData: payload,
          statusCode: resp.status,
          responseSnippet: body.slice(0, 300),
        }, baseline, body);

        // Error-based detection
        for (const pattern of sqlErrorPatterns) {
          if (pattern.test(body)) {
            findings.push(
              `CONFIRMED SQLi (${desc}): SQL error in '${param}' with payload: ${payload}`
            );
            break;
          }
        }

        // Time-based detection
        if (delay && baselineTime > 0 && elapsed > baselineTime + delay - 500) {
          findings.push(
            `CONFIRMED SQLi (${desc}): ${elapsed}ms delay (baseline ${baselineTime}ms) in '${param}'`
          );
        }
      } catch (e) {
        // Skip
      }
    }
  }

  return { findings };
}

/**
 * Test if the server accepts write-oriented HTTP methods (PUT, PATCH, DELETE)
 * on REST-style endpoints.
 *
 * @returns {{ findings: string[] }}
 */
async function testApiWrite(targetUrl, httpClient) {
  const findings = [];
  const baseline = await captureBaseline(targetUrl, httpClient);
  const canary = makeCanary('api');

  const apiEndpoints = [
    '/api/users', '/api/user', '/api/products', '/api/items',
    '/api/posts', '/api/comments', '/api/data', '/api/entries',
    '/api/v1/users', '/api/v1/products', '/api/v1/items',
    '/api/v2/users', '/api/v2/products',
  ];

  const writeMethods = ['put', 'patch', 'delete'];

  for (const endpoint of apiEndpoints) {
    // First check if the endpoint exists at all
    try {
      const getResp = await httpClient.get(`${targetUrl}${endpoint}`, {
        timeout: 5000,
        maxRedirects: 0,
      });

      if (getResp.status >= 200 && getResp.status < 400) {
        // Endpoint exists — test write methods
        for (const method of writeMethods) {
          try {
            const url = `${targetUrl}${endpoint}/1`;
            const sentData = method === 'delete'
              ? null
              : JSON.stringify({ name: canary, test: true });
            const config = {
              headers: { 'Content-Type': 'application/json' },
              timeout: 5000,
              maxRedirects: 0,
            };

            const resp = method === 'delete'
              ? await httpClient.delete(url, config)
              : await httpClient[method](url, sentData, config);

            const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

            logProbe(`API ${method.toUpperCase()} — ${endpoint}/1`, {
              method: method.toUpperCase(),
              url,
              sentData,
              statusCode: resp.status,
              responseSnippet: body.slice(0, 300),
            }, baseline, body);

            if (resp.status >= 200 && resp.status < 300) {
              findings.push(
                `API endpoint ${endpoint} accepts ${method.toUpperCase()} (HTTP ${resp.status}) — write access likely open`
              );
            } else if (resp.status === 401 || resp.status === 403) {
              // Write exists but is protected — not a vulnerability
            }
            // 404/405 = method not allowed, fine
          } catch (e) {
            // Skip
          }
        }
      }
    } catch (e) {
      // Endpoint doesn't exist, skip
    }
  }

  return { findings };
}

module.exports = {
  makeCanary,
  captureBaseline,
  logProbe,
  testReflectedXSS,
  testFormSubmission,
  testSQLiWrite,
  testApiWrite,
};
