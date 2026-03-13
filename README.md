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

## 🧩 Available Scans

The scanner includes over 50+ specialized modules categorized by vulnerability type:

### 🔴 Critical Severity (RCE & Deep Exploits)
| ID | Name | Description |
|---|---|---|
| CVE-2021-44228 | **Log4Shell** | Java JNDI injection (vulnerable Log4j). |
| CVE-2025-66478 | **Next.js RSC RCE** | Insecure deserialization in RSC Flight protocol. |
| CVE-2024-4577 | **PHP-CGI RCE** | CGI argument injection on Windows systems. |
| CVE-2024-8926 | **PHP-CGI OS RCE** | OS command injection via CGI query strings. |
| CVE-2021-3129 | **Laravel RCE** | Unauthenticated RCE in Ignition debug mode. |
| CVE-2017-9841 | **PHPUnit RCE** | Remote execution via exposed eval-stdin.php. |
| CVE-2019-11043 | **PHP-FPM RCE** | Buffer underflow in PHP-FPM + Nginx setups. |
| CVE-2024-1874 | **PHP Batch RCE** | Command injection via Windows .bat/.cmd files. |
| CVE-2025-55182 | **React Shell RCE** | Exposed interactive debug/shell endpoints. |
| ENV-EXPOSURE | **Exposed .env** | Critical leak of production API keys & secrets. |
| PYTHON-DEBUG | **Python Debug** | Exposed Flask/Django/FastAPI debug consoles. |

### 🟠 High Severity (SSRF, SQLi, Data Leaks)
| ID | Name | Description |
|---|---|---|
| CVE-2024-34351 | **Next.js Image SSRF** | SSRF in Image Optimization & Server Actions. |
| CVE-2025-57822 | **Middleware SSRF** | Header-forwarding SSRF in Next.js middleware. |
| CVE-2025-29927 | **Auth Bypass** | Middleware bypass via internal Next.js headers. |
| CVE-2025-1735 | **PHP pgsql SQLi** | SQL injection in PHP's PostgreSQL extension. |
| CVE-2024-23897 | **SQL Injection** | Generic database error-based SQLi probes. |
| CVE-2024-47176 | **Generic SSRF** | Probes for metadata and internal resource leaks. |
| GIT-EXPOSURE | **Exposed .git** | Leaked source code and repository structure. |
| SVN-EXPOSURE | **Exposed .svn** | Leaked Subversion repository metadata. |
| DOCKER-COMPOSE | **Docker Compose** | Exposure of infrastructure YAML configuration. |
| LARAVEL-LOGS | **Laravel Logs** | Sensitive traces leaked in laravel.log files. |
| PHP-SESSION | **PHP Sessions** | Exposed session storage files (hijacking risk). |
| PHPMYADMIN | **phpMyAdmin** | Exposed database management login interfaces. |
| BACKUP-FILES | **Backup Leaks** | Exposed .sql, .zip, and .bak archive files. |

### 🟡 Medium Severity (Information & Config)
| ID | Name | Description |
|---|---|---|
| CVE-2025-55183 | **Source Disclosure** | Server function source code leakage in Next.js. |
| CVE-2024-21534 | **Info Disclosure** | Next.js internal manifest and path exposure. |
| NEXTJS-DATA-LEAK | **Next.js Data Leak** | Secrets leaked in client-side `__NEXT_DATA__`. |
| SWAGGER-UI | **Swagger UI** | Exposed API documentation and endpoints. |
| GRAPHQL-INTROS | **GQL Introspection** | Enabled GraphQL schema exploration queries. |
| DIRECTORY-LIST | **Directory Listing** | Detection of enabled "Index of /" views. |
| SENSITIVE-LOGS | **Sensitive Logs** | Exposed error.log, access.log, npm-debug.log. |
| WP-ADMIN | **WordPress Admin** | Discovery of exposed WP admin/login pages. |
| WP-XMLRPC | **WP XML-RPC** | Enabled XML-RPC (amplification/brute-force). |
| GENERIC-REDIRECT | **Open Redirect** | Phishing vector via common redirect params. |
| CVE-2024-5458 | **PHP Filter Bypass** | Bypasses in standard PHP security filters. |
| SEC-HEADERS | **Security Headers** | Analysis of HSTS, CSP, XFO, and other headers. |

### 🔵 Low Severity (Metadata & Best Practices)
| ID | Name | Description |
|---|---|---|
| NPM-PACKAGE-JSON | **package.json** | Dependency and project metadata disclosure. |
| DOCKERFILE | **Dockerfile** | Disclosure of build steps and base images. |
| GITLAB-CI | **GitLab CI Config** | Leaked CI/CD pipeline and runner details. |
| WP-VERSION | **WP Version** | Disclosure of WordPress version in meta tags. |
| DS-STORE | **.DS_Store** | macOS directory metadata file exposure. |
| COOKIE-SEC | **Cookie Security** | Missing HttpOnly/Secure flags on sensitive cookies. |

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
