/**
 * CVE Module Auto-Discovery
 *
 * Automatically loads all .js files in this directory (except index.js)
 * as CVE scanner modules. Each module must export:
 *   - id: string (CVE ID or check name)
 *   - name: string (human-readable name)
 *   - severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
 *   - description: string
 *   - scan(targetUrl, httpClient): Promise<{vulnerable, details, evidence?}>
 */

const fs = require('fs');
const path = require('path');

const modules = [];
const dir = __dirname;

const files = fs.readdirSync(dir).filter((f) => {
  return f.endsWith('.js') && f !== 'index.js';
});

for (const file of files.sort()) {
  try {
    const mod = require(path.join(dir, file));
    if (mod && mod.id && typeof mod.scan === 'function') {
      modules.push(mod);
    }
  } catch (err) {
    console.error(`Warning: Failed to load module ${file}: ${err.message}`);
  }
}

module.exports = modules;
