/**
 * BACKUP-FILES - Exposed Backup and Archive Files
 * 
 * This module probes for common backup filenames and extensions 
 * which can leak entire database dumps or full source code archives.
 */

module.exports = {
  id: 'BACKUP-FILES',
  name: 'Exposed Backup Files',
  severity: 'HIGH',
  description: 'Detects exposed backup and archive files which can leak sensitive data/source code.',
  references: ['https://cwe.mitre.org/data/definitions/200.html'],

  async scan(targetUrl, httpClient) {
    const files = [
      'backup.sql', 
      'dump.sql', 
      'database.sql', 
      'backup.zip', 
      'site.zip', 
      'archive.tar.gz', 
      'data.bak', 
      'config.bak'
    ];
    const baseUrl = targetUrl.replace(/\/$/, '');
    const findings = [];

    for (const file of files) {
      try {
        const url = `${baseUrl}/${file}`;
        const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false, responseType: 'arraybuffer' });
        if (resp.status === 200 && resp.data.byteLength > 100) {
          findings.push(file);
        }
      } catch (e) {}
    }

    if (findings.length > 0) {
      return {
        vulnerable: true,
        details: `Found exposed backup files: ${findings.join(', ')}`,
        evidence: `Files: ${findings.join(', ')}`
      };
    }
    return { vulnerable: false };
  }
};
