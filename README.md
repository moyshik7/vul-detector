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
| 🔴 CRITICAL | CVE-2021-44228 | **Log4Shell** — Probes for Java JNDI injection vulnerabilities. |
| 🔴 CRITICAL | CVE-2025-55182 | **React Shell RCE** — Detects exposed debug tools and shell endpoints. |
| 🔴 CRITICAL | CVE-2024-23897 | **SQL Injection** — Tests payloads and detects DB error messages. |
| 🔴 CRITICAL | CVE-2024-47176 | **SSRF** — Checks for internal resource access and metadata leaks. |
| 🟠 HIGH | CVE-2024-21535 | **Reflected XSS** — Tests for unescaped input reflection. |
| 🟠 HIGH | CVE-2024-21412 | **Path Traversal** — Checks for sensitive files like `.env`, `.git/config`. |
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

MIT
