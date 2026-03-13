# ⚡ VUL-DETECTOR

A fast, modular Node.js vulnerability scanner designed to detect known CVEs and common security misconfigurations in web applications.

## 🚀 Features

- **Modular Architecture**: All vulnerability checks are self-contained modules in the `cves/` folder.
- **Dynamic Discovery**: Automatically loads any `.js` file added to the `cves/` directory.
- **19+ Included Modules**: Covers critical CVEs like Log4Shell, React Shell RCE, SQL Injection, SSRF, and more.
- **Rich CLI Output**: Beautiful, colored tables with severity icons and detailed scan summaries.
- **Flexible Filtering**: Run specific CVEs or filter by minimum severity (CRITICAL, HIGH, etc.).

## 📦 Installation

Install globally using npm:

```bash
npm install -g vul-detector
```

Or run without installing using npx:

```bash
npx vul-detector --target https://example.com
```

## 🛠 Usage

Basic scan:
```bash
vul-detector --target https://example.com
```

Verbose scan (shows progress for each module):
```bash
vul-detector --target https://example.com --verbose
```

Scan for a specific CVE only:
```bash
vul-detector --target https://example.com --cve CVE-2025-55182
```

Filter by minimum severity:
```bash
vul-detector --target https://example.com --severity HIGH
```

Full options:
```bash
vul-detector --help
```

## 🧩 Included CVE Modules (Samples)

| Severity | Module | Description |
|---|---|---|
| 🔴 CRITICAL | CVE-2024-4577 | **PHP-CGI RCE** — Critical argument injection in PHP-CGI on Windows. |
| 🔴 CRITICAL | CVE-2024-8926 | **PHP-CGI OS RCE** — OS command injection via PHP-CGI query strings. |
| 🔴 CRITICAL | CVE-2021-3129 | **Laravel RCE** — Unauthenticated RCE in Laravel Ignition debug mode. |
| 🔴 CRITICAL | CVE-2017-9841 | **PHPUnit RCE** — Critical unauthenticated RCE in exposed PHPUnit files. |
| 🔴 CRITICAL | CVE-2019-11043 | **PHP-FPM RCE** — Buffer underflow in PHP-FPM with Nginx setup. |
| 🔴 CRITICAL | CVE-2024-1874 | **PHP Batch RCE** — Command injection via .bat/.cmd file execution. |
| 🔴 CRITICAL | CVE-2025-66478 | **Next.js RSC RCE** — Probes for insecure deserialization in Flight protocol. |
| 🔴 CRITICAL | CVE-2024-34351 | **Next.js Image SSRF** — Tests for SSRF in Image Optimization & Server Actions. |
| 🟠 HIGH | CVE-2025-1735 | **PHP pgsql SQLi** — SQL injection in core PHP PostgreSQL extension. |
| 🟠 HIGH | PHP-SESSION-EXPOSURE | **PHP Session Leak** — Probes for exposed PHP session storage files. |
| 🟠 HIGH | CVE-2025-55183 | **Next.js Source Disclosure** — Probes for server function source code leakage. |
| 🟠 HIGH | NEXTJS-INTERNAL-DATA | **Next.js Data Leak** — Scans `__NEXT_DATA__` for leaked secrets/API keys. |
| 🟡 MEDIUM | PHP-INFO-EXPOSURE | **PHP Info Exposure** — Checks for exposed `phpinfo()` diagnostic pages. |
| 🟡 MEDIUM | CVE-2024-5458 | **PHP Filter Bypass** — Tests for bypasses in PHP standard filters. |
| 🟡 MEDIUM | NEXTJS-DEV-EXPOSURE | **Next.js Dev Exposure** — Checks for exposed dev/telemetry endpoints. |
| 🟡 MEDIUM | SEC-HEADERS | **Security Headers** — Analyzes HSTS, CSP, X-Frame-Options, etc. |

## 🛠 Adding Your Own CVE Modules

1. Create a new `.js` file in the `cves/` folder.
2. Export an object adhering to the module interface:

```javascript
module.exports = {
  id: 'CVE-XXXX-XXXXX',
  name: 'Vulnerability Name',
  severity: 'HIGH', // CRITICAL, HIGH, MEDIUM, LOW, INFO
  description: 'Detailed description...',
  references: ['https://link-to-cve'],
  async scan(targetUrl, httpClient) {
    // Perform your logic using the provided axios instance (httpClient)
    // Return: { vulnerable: boolean, details: string, evidence: string }
    return {
      vulnerable: true,
      details: 'Found a specific indicator',
      evidence: 'Raw data found in response'
    };
  }
};
```

The app will automatically detect and load your new module on the next run.

## ⚠️ Disclaimer

**This tool is for educational and authorized security testing purposes only.** Scanning targets without explicit permission is illegal and unethical. The authors are not responsible for any misuse of this tool.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
