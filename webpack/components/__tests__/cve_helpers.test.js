/* eslint-disable import/no-unresolved */
import {
  severityRank,
  riskLevelFromWorst,
  formatDateTime,
  compareStrings,
  compareScanFindings,
  summarizeComparison,
} from '../cve_helpers';

describe('cve_helpers', () => {
  it('maps severity ranks', () => {
    expect(severityRank('CRITICAL')).toBe(4);
    expect(severityRank('high')).toBe(3);
    expect(severityRank('MEDIUM')).toBe(2);
    expect(severityRank('low')).toBe(1);
    expect(severityRank('unknown')).toBe(0);
  });

  it('maps risk levels from worst', () => {
    expect(riskLevelFromWorst('critical')).toBe('high');
    expect(riskLevelFromWorst('high')).toBe('high');
    expect(riskLevelFromWorst('medium')).toBe('medium');
    expect(riskLevelFromWorst('low')).toBe('low');
    expect(riskLevelFromWorst('none')).toBe('none');
  });

  it('formats dates into yyyy-mm-dd hh:mm', () => {
    const result = formatDateTime('2026-02-22T10:05:00Z');
    expect(result).toContain('2026-02-22');
    expect(result).toContain('10:05');
  });

  it('returns input when date is invalid', () => {
    expect(formatDateTime('not-a-date')).toBe('not-a-date');
  });

  it('compares strings safely', () => {
    expect(compareStrings('a', 'b')).toBeLessThan(0);
    expect(compareStrings('b', 'a')).toBeGreaterThan(0);
    expect(compareStrings('a', 'a')).toBe(0);
    expect(compareStrings(null, 'a')).toBeLessThan(0);
  });

  it('builds comparison rows for scan findings', () => {
    const previousFindings = [
      { id: 'CVE-1', name: 'pkg-a', severity: 'HIGH', version: '1.0' },
      { id: 'CVE-2', name: 'pkg-b', severity: 'LOW', version: '1.0' },
      { id: 'CVE-3', name: 'pkg-c', severity: 'LOW', version: '1.0' },
      { id: 'CVE-4', name: 'pkg-d', severity: 'MEDIUM', version: '1.0' },
    ];
    const currentFindings = [
      { id: 'CVE-1', name: 'pkg-a', severity: 'CRITICAL', version: '1.0' },
      { id: 'CVE-2', name: 'pkg-b', severity: 'LOW', version: '2.0' },
      { id: 'CVE-4', name: 'pkg-d', severity: 'MEDIUM', version: '1.0' },
      { id: 'CVE-5', name: 'pkg-e', severity: 'HIGH', version: '1.0' },
    ];

    const rows = compareScanFindings(previousFindings, currentFindings);
    const statusesById = Object.fromEntries(rows.map(row => [row.id, row.status]));

    expect(statusesById['CVE-1']).toBe('severity_changed');
    expect(statusesById['CVE-2']).toBe('updated');
    expect(statusesById['CVE-3']).toBe('resolved');
    expect(statusesById['CVE-4']).toBe('unchanged');
    expect(statusesById['CVE-5']).toBe('new');
  });

  it('summarizes comparison rows by status', () => {
    const summary = summarizeComparison([
      { status: 'new' },
      { status: 'resolved' },
      { status: 'severity_changed' },
      { status: 'updated' },
      { status: 'unchanged' },
      { status: 'new' },
    ]);

    expect(summary.new).toBe(2);
    expect(summary.resolved).toBe(1);
    expect(summary.severity_changed).toBe(1);
    expect(summary.updated).toBe(1);
    expect(summary.unchanged).toBe(1);
  });
});
