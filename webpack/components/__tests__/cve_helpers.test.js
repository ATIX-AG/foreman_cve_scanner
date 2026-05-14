/* eslint-disable import/no-unresolved */
import {
  severityRank,
  riskLevelFromWorst,
  formatDateTime,
  compareStrings,
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

});
