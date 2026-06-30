/* eslint-disable import/no-unresolved */
import {
  findingIdentity,
  severityRank,
  riskLevelFromWorst,
  formatDateTime,
  formatScanOrigin,
  formatScannedAt,
  compareStrings,
  visibleScanSource,
  katelloFixLabel,
  katelloFixTitle,
  katelloFixCounts,
  katelloFixErrataSearch,
  katelloFixInstallUrl,
  shouldShowKatelloFixColumn,
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

  it('formats scan origin without rex source noise', () => {
    expect(formatScanOrigin('trivy', 'rex')).toBe('trivy');
    expect(formatScanOrigin('grype', 'external')).toBe('grype / external');
  });

  it('formats scanned_at with unknown fallback', () => {
    expect(formatScannedAt('2026-02-22T10:05:00Z')).toContain('2026-02-22');
    expect(formatScannedAt('')).toBe('Unknown time');
  });

  it('compares strings safely', () => {
    expect(compareStrings('a', 'b')).toBeLessThan(0);
    expect(compareStrings('b', 'a')).toBeGreaterThan(0);
    expect(compareStrings('a', 'a')).toBe(0);
    expect(compareStrings(null, 'a')).toBeLessThan(0);
  });

  it('hides rex source and keeps external source visible', () => {
    expect(visibleScanSource('rex')).toBe('');
    expect(visibleScanSource('external')).toBe('external');
  });

  it('builds finding identity from cve and package', () => {
    expect(findingIdentity({ id: 'CVE-2026-0001', name: 'openssl' })).toBe(
      'CVE-2026-0001::openssl'
    );
  });

  it('formats fix availability status labels and titles', () => {
    const fix = {
      status: 'installable',
      errata: [{ errata_id: 'RHSA-2026:0001' }],
    };

    expect(katelloFixLabel(fix)).toBe('Installable');
    expect(katelloFixTitle(fix)).toContain('RHSA-2026:0001');
  });

  it('hides fix availability column when findings are not enriched', () => {
    expect(
      shouldShowKatelloFixColumn([
        {
          id: 'CVE-2026-0001',
        },
      ])
    ).toBe(false);

    expect(
      shouldShowKatelloFixColumn([
        {
          katello_fix: {
            status: 'applicable',
            reason: null,
          },
        },
      ])
    ).toBe(true);
  });

  it('counts fix availability statuses', () => {
    expect(
      katelloFixCounts([
        { katello_fix: { status: 'installable' } },
        { katello_fix: { status: 'installable' } },
        { katello_fix: { status: 'applicable' } },
        { katello_fix: { status: 'unavailable' } },
      ])
    ).toEqual({ installable: 2, applicable: 1 });
  });

  it('builds errata install remote execution urls for installable fixes', () => {
    const fix = {
      status: 'installable',
      errata: [{ errata_id: 'RHSA-2026:0001' }],
    };
    const url = katelloFixInstallUrl({ hostName: 'host.example.com', fix });
    const params = new URL(url, 'http://example.test').searchParams;

    expect(katelloFixErrataSearch(fix)).toBe('errata_id = RHSA-2026:0001');
    expect(url).toContain('/job_invocations/new?');
    expect(params.get('feature')).toBe('katello_errata_install_by_search');
    expect(params.get('search')).toBe('name ^ (host.example.com)');
    expect(params.get('inputs[Errata search query]')).toBe(
      'errata_id = RHSA-2026:0001'
    );
  });

  it('does not build install urls for non-installable fixes', () => {
    expect(
      katelloFixInstallUrl({
        hostName: 'host.example.com',
        fix: {
          status: 'applicable',
          errata: [{ errata_id: 'RHSA-2026:0001' }],
        },
      })
    ).toBe('');
  });
});
