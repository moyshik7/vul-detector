const axios = require('axios');
const cveModules = require('../cves');

class Scanner {
  constructor(options = {}) {
    this.timeout = options.timeout || 10000;
    this.verbose = options.verbose || false;
    this.cveFilter = options.cveFilter || null;
    this.verifyWrite = options.verifyWrite || false;
    this.modules = [];

    // Create a shared HTTP client
    this.httpClient = axios.create({
      timeout: this.timeout,
      maxRedirects: 5,
      validateStatus: () => true, // Don't throw on any HTTP status
      headers: {
        'User-Agent': 'VulDetector/1.0 Security Scanner',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
      },
    });
  }

  /**
   * Load CVE modules from the cves/ directory.
   * If a cveFilter is set, only load the matching module.
   * @returns {number} Number of loaded modules
   */
  loadModules() {
    let modules = cveModules;

    if (this.cveFilter) {
      modules = modules.filter(
        (m) => m.id.toLowerCase() === this.cveFilter.toLowerCase()
      );
    }

    this.modules = modules;
    return this.modules.length;
  }

  /**
   * Run all loaded CVE modules against the target URL.
   * @param {string} targetUrl - The URL to scan
   * @returns {Promise<Array>} Array of scan results
   */
  async scan(targetUrl) {
    const results = [];
    const chalk = require('chalk');

    for (const mod of this.modules) {
      const label = `  [${mod.id || mod.name}]`;

      if (this.verbose) {
        process.stdout.write(chalk.gray(`${label} Scanning... `));
      }

      try {
        const result = await mod.scan(targetUrl, this.httpClient, { verifyWrite: this.verifyWrite });

        results.push({
          id: mod.id,
          name: mod.name,
          severity: mod.severity,
          description: mod.description,
          references: mod.references || [],
          vulnerable: result.vulnerable,
          details: result.details,
          evidence: result.evidence || null,
        });

        if (this.verbose) {
          if (result.vulnerable) {
            console.log(chalk.redBright('VULNERABLE ✗'));
          } else {
            console.log(chalk.greenBright('SAFE ✓'));
          }
        }
      } catch (err) {
        results.push({
          id: mod.id,
          name: mod.name,
          severity: mod.severity,
          description: mod.description,
          references: mod.references || [],
          vulnerable: false,
          details: `Scan error: ${err.message}`,
          evidence: null,
          error: true,
        });

        if (this.verbose) {
          console.log(chalk.yellowBright(`ERROR: ${err.message}`));
        }
      }
    }

    return results;
  }
}

module.exports = { Scanner };
