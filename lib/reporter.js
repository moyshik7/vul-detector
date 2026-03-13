const chalk = require('chalk');
const Table = require('cli-table3');

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const SEVERITY_COLORS = {
  CRITICAL: chalk.bgRedBright.whiteBright.bold,
  HIGH: chalk.redBright.bold,
  MEDIUM: chalk.yellowBright.bold,
  LOW: chalk.blueBright.bold,
  INFO: chalk.cyanBright,
};

const SEVERITY_ICONS = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '🔵',
  INFO: 'ℹ️ ',
};

class Reporter {
  constructor(options = {}) {
    this.minSeverity = options.minSeverity || 'INFO';
  }

  /**
   * Filter results based on minimum severity.
   */
  filterBySeverity(results) {
    const minIdx = SEVERITY_ORDER.indexOf(this.minSeverity);
    if (minIdx === -1) return results;
    return results.filter((r) => {
      const idx = SEVERITY_ORDER.indexOf(r.severity);
      return idx !== -1 && idx <= minIdx;
    });
  }

  /**
   * Print the detailed results table.
   */
  printResults(results) {
    const filtered = this.filterBySeverity(results);

    // Sort: vulnerable first, then by severity
    filtered.sort((a, b) => {
      if (a.vulnerable !== b.vulnerable) return a.vulnerable ? -1 : 1;
      return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    });

    // Vulnerabilities Found
    const vulns = filtered.filter((r) => r.vulnerable);
    const safe = filtered.filter((r) => !r.vulnerable);

    if (vulns.length > 0) {
      console.log(chalk.redBright.bold('  ⚠  VULNERABILITIES FOUND\n'));

      const table = new Table({
        head: [
          chalk.whiteBright.bold('Severity'),
          chalk.whiteBright.bold('CVE / Check'),
          chalk.whiteBright.bold('Name'),
          chalk.whiteBright.bold('Details'),
        ],
        colWidths: [12, 20, 28, 45],
        style: { 'padding-left': 1, 'padding-right': 1 },
        wordWrap: true,
      });

      for (const r of vulns) {
        const colorFn = SEVERITY_COLORS[r.severity] || chalk.white;
        const icon = SEVERITY_ICONS[r.severity] || '';

        table.push([
          `${icon} ${colorFn(r.severity)}`,
          chalk.whiteBright(r.id),
          chalk.white(r.name),
          chalk.gray(r.details),
        ]);

        // Show evidence if present
        if (r.evidence) {
          table.push([
            { content: '', colSpan: 1 },
            { content: chalk.gray('Evidence:'), colSpan: 1 },
            { content: chalk.yellowBright(r.evidence), colSpan: 2 },
          ]);
        }
      }

      console.log(table.toString());
      console.log();
    } else {
      console.log(chalk.greenBright.bold('  ✓  No vulnerabilities detected!\n'));
    }

    // Safe checks
    if (safe.length > 0) {
      console.log(chalk.greenBright.bold('  ✓  PASSED CHECKS\n'));

      const safeTable = new Table({
        head: [
          chalk.whiteBright.bold('Status'),
          chalk.whiteBright.bold('CVE / Check'),
          chalk.whiteBright.bold('Name'),
          chalk.whiteBright.bold('Details'),
        ],
        colWidths: [10, 20, 28, 45],
        style: { 'padding-left': 1, 'padding-right': 1 },
        wordWrap: true,
      });

      for (const r of safe) {
        const statusText = r.error
          ? chalk.yellowBright('⚠ ERR')
          : chalk.greenBright('✓ PASS');

        safeTable.push([
          statusText,
          chalk.gray(r.id),
          chalk.gray(r.name),
          chalk.gray(r.details),
        ]);
      }

      console.log(safeTable.toString());
      console.log();
    }
  }

  /**
   * Print a summary of the scan.
   */
  printSummary(results, targetUrl, elapsed) {
    const vulns = results.filter((r) => r.vulnerable);
    const counts = {};

    for (const sev of SEVERITY_ORDER) {
      counts[sev] = vulns.filter((r) => r.severity === sev).length;
    }

    console.log(chalk.whiteBright('  ─────────────────────────────────────────────────────────'));
    console.log(chalk.bold.whiteBright('  SCAN SUMMARY\n'));
    console.log(chalk.whiteBright(`  Target:         ${chalk.cyanBright.underline(targetUrl)}`));
    console.log(chalk.whiteBright(`  Duration:       ${chalk.greenBright(elapsed + 's')}`));
    console.log(chalk.whiteBright(`  Total checks:   ${chalk.whiteBright(results.length)}`));
    console.log(chalk.whiteBright(`  Vulnerabilities:${vulns.length > 0 ? chalk.redBright(' ' + vulns.length) : chalk.greenBright(' 0')}`));

    if (vulns.length > 0) {
      const parts = [];
      if (counts.CRITICAL > 0) parts.push(chalk.bgRedBright.whiteBright(` ${counts.CRITICAL} CRITICAL `));
      if (counts.HIGH > 0) parts.push(chalk.redBright(`${counts.HIGH} HIGH`));
      if (counts.MEDIUM > 0) parts.push(chalk.yellowBright(`${counts.MEDIUM} MEDIUM`));
      if (counts.LOW > 0) parts.push(chalk.blueBright(`${counts.LOW} LOW`));
      if (counts.INFO > 0) parts.push(chalk.cyanBright(`${counts.INFO} INFO`));
      console.log(chalk.whiteBright('  Breakdown:      ') + parts.join(chalk.gray(' | ')));
    }

    console.log(chalk.whiteBright('\n  ─────────────────────────────────────────────────────────\n'));

    if (vulns.length > 0) {
      console.log(chalk.yellowBright('  ⚠  Review the vulnerabilities above and take appropriate action.\n'));
    } else {
      console.log(chalk.greenBright('  ✓  No vulnerabilities found. Target appears secure against tested CVEs.\n'));
    }
  }
}

module.exports = { Reporter };
