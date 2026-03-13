/**
 * DS-STORE-EXPOSURE - Exposed .DS_Store Metadata
 * 
 * This module probes for exposed .DS_Store files which can leak 
 * directory structure and file names on macOS-hosted systems.
 */

module.exports = {
  id: 'DS-STORE-EXPOSURE',
  name: 'Exposed .DS_Store Metadata',
  severity: 'LOW',
  description: 'Detects exposed .DS_Store files which can leak directory structure and file names.',
  references: ['https://en.wikipedia.org/wiki/.DS_Store'],

  async scan(targetUrl, httpClient) {
    const url = `${targetUrl.replace(/\/$/, '')}/.DS_Store`;
    try {
      const resp = await httpClient.get(url, { timeout: 5000, validateStatus: false, responseType: 'arraybuffer' });
      if (resp.status === 200) {
        return {
          vulnerable: true,
          details: 'Found exposed .DS_Store metadata file.',
          evidence: `Status: ${resp.status}, Size: ${resp.data.byteLength} bytes`
        };
      }
    } catch (e) {}
    return { vulnerable: false };
  }
};
