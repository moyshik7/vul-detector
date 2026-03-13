#!/usr/bin/env node

const { Command } = require('commander');
const chalk = require('chalk');
const { Scanner } = require('./lib/scanner');
const { Reporter } = require('./lib/reporter');

const banner = `
${chalk.redBright('╔══════════════════════════════════════════════════════════╗')}
${chalk.redBright('║')}  ${chalk.bold.whiteBright('⚡ VUL-DETECTOR')} ${chalk.gray('— CVE Vulnerability Scanner')}            ${chalk.redBright('║')}
${chalk.redBright('║')}  ${chalk.gray('Scan websites for known CVE vulnerabilities')}             ${chalk.redBright('║')}
${chalk.redBright('╚══════════════════════════════════════════════════════════╝')}
`;

const program = new Command();

program
  .name('vul-detector')
  .description('Scan websites for known CVE vulnerabilities')
  .version('1.0.0')
  .requiredOption('-t, --target <url>', 'Target URL to scan (e.g. https://example.com)')
  .option('-c, --cve <id>', 'Run a specific CVE module only (e.g. CVE-2025-55182)')
  .option('-s, --severity <level>', 'Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW, INFO)', 'INFO')
  .option('--timeout <ms>', 'Request timeout in milliseconds', '10000')
  .option('--no-color', 'Disable colored output')
  .option('-v, --verbose', 'Show detailed scan progress')
  .parse(process.argv);

const options = program.opts();

(async () => {
  console.log(banner);

  // Normalize target URL
  let targetUrl = options.target.trim();
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }
  // Remove trailing slash
  targetUrl = targetUrl.replace(/\/+$/, '');

  console.log(chalk.whiteBright('  Target: ') + chalk.cyanBright.underline(targetUrl));
  console.log(chalk.whiteBright('  Time:   ') + chalk.gray(new Date().toISOString()));
  
  if (options.cve) {
    console.log(chalk.whiteBright('  Filter: ') + chalk.yellowBright(options.cve));
  }
  console.log();

  // Initialize scanner
  const scanner = new Scanner({
    timeout: parseInt(options.timeout, 10),
    verbose: options.verbose || false,
    cveFilter: options.cve || null,
  });

  // Load modules
  const moduleCount = scanner.loadModules();
  console.log(chalk.whiteBright(`  Loaded ${chalk.greenBright(moduleCount)} CVE module(s)\n`));

  if (moduleCount === 0) {
    console.log(chalk.yellowBright('  ⚠  No CVE modules found. Add .js files to the cves/ folder.\n'));
    process.exit(0);
  }

  // Run scan
  console.log(chalk.whiteBright('  ─────────────────────────────────────────────────────────'));
  console.log(chalk.bold.whiteBright('  SCANNING...\n'));

  const startTime = Date.now();
  const results = await scanner.scan(targetUrl);
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

  console.log(chalk.whiteBright(`\n  Scan completed in ${chalk.greenBright(elapsed + 's')}\n`));

  // Report results
  const reporter = new Reporter({
    minSeverity: options.severity.toUpperCase(),
  });

  reporter.printResults(results);
  reporter.printSummary(results, targetUrl, elapsed);
})();
