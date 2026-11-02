'use strict';

/**
 * CodeVault — SHA-256 Tamper-Evident Forensic Audit Chain
 * Every scan is cryptographically linked to the previous one.
 * Altering any entry breaks the chain — mathematically detectable.
 */

const crypto = require('crypto');

class AuditChain {
  constructor() {
    this.entries = [];
    this.currentTipHash = 'GENESIS';
  }

  /**
   * Hash a string with SHA-256.
   */
  _sha256(str) {
    return crypto.createHash('sha256').update(str).digest('hex');
  }

  /**
   * Append a scan result to the chain.
   * @param {string} scanId
   * @param {string} rawCode - the code that was scanned
   * @param {object} scanResult - output from scanner.scan()
   * @returns {object} chain entry with hash and prev_hash
   */
  append(scanId, rawCode, scanResult) {
    const timestamp = new Date().toISOString();
    const codeHash = this._sha256(rawCode);
    const findingsHash = this._sha256(JSON.stringify(scanResult.findings));
    const prevHash = this.currentTipHash;
    const index = this.entries.length;

    // Canonical payload — everything except the final hash
    const payload = JSON.stringify({
      index,
      timestamp,
      scan_id: scanId,
      code_hash: codeHash,
      findings_hash: findingsHash,
      finding_count: scanResult.finding_count,
      severity_score: scanResult.severity_score,
      risk_level: scanResult.risk_level,
      prev_hash: prevHash,
    });

    const hash = this._sha256(payload);

    const entry = {
      index,
      timestamp,
      scan_id: scanId,
      code_hash: codeHash,
      findings_hash: findingsHash,
      finding_count: scanResult.finding_count,
      severity_score: scanResult.severity_score,
      risk_level: scanResult.risk_level,
      prev_hash: prevHash,
      hash,
    };

    this.entries.push(entry);
    this.currentTipHash = hash;
    return entry;
  }

  /**
   * Verify the entire chain from genesis to tip.
   * @returns {{ intact: boolean, entry_count: number, broken_at?: number }}
   */
  verify() {
    if (this.entries.length === 0) {
      return { intact: true, entry_count: 0 };
    }

    for (let i = 0; i < this.entries.length; i++) {
      const e = this.entries[i];

      // Recompute the expected hash
      const payload = JSON.stringify({
        index: e.index,
        timestamp: e.timestamp,
        scan_id: e.scan_id,
        code_hash: e.code_hash,
        findings_hash: e.findings_hash,
        finding_count: e.finding_count,
        severity_score: e.severity_score,
        risk_level: e.risk_level,
        prev_hash: e.prev_hash,
      });
      const expectedHash = this._sha256(payload);

      if (e.hash !== expectedHash) {
        return { intact: false, entry_count: this.entries.length, broken_at: i };
      }

      // Check chain linkage
      if (i > 0 && e.prev_hash !== this.entries[i - 1].hash) {
        return { intact: false, entry_count: this.entries.length, broken_at: i };
      }

      if (i === 0 && e.prev_hash !== 'GENESIS') {
        return { intact: false, entry_count: this.entries.length, broken_at: 0 };
      }
    }

    return {
      intact: true,
      entry_count: this.entries.length,
      tip_hash: this.currentTipHash,
    };
  }

  /**
   * Get the last N entries (most recent first).
   */
  getChain(limit = 50) {
    return [...this.entries].reverse().slice(0, limit);
  }

  /**
   * Get a single entry by scan_id.
   */
  getEntry(scanId) {
    return this.entries.find(e => e.scan_id === scanId) || null;
  }

  /**
   * Get chain statistics.
   */
  getStats() {
    const total = this.entries.length;
    const clean = this.entries.filter(e => e.risk_level === 'CLEAN').length;
    const critical = this.entries.filter(e => e.risk_level === 'CRITICAL').length;
    return {
      total_scans: total,
      clean_scans: clean,
      critical_scans: critical,
      chain_intact: this.verify().intact,
      tip_hash: this.currentTipHash,
    };
  }
}

module.exports = AuditChain;
