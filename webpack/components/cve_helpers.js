/* eslint-disable import/no-unresolved */
import { translate as __ } from 'foremanReact/common/I18n';

const SEVERITY_RANK = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};
const COMPARE_STATUS_RANK = {
  new: 4,
  resolved: 3,
  updated: 2,
  unchanged: 1,
};
const KATELLO_FIX_RANK = {
  installable: 3,
  applicable: 2,
  unavailable: 1,
  unknown: 0,
};
const KATELLO_ERRATA_INSTALL_FEATURE = 'katello_errata_install_by_search';
const ERRATA_SEARCH_INPUT = 'Errata search query';
const COMPARISON_DIFF_LABELS = {
  severity: __('Severity'),
  version: __('Version'),
  fixed: __('Fixed'),
  scan_status: __('Scan status'),
  title: __('Title'),
  published: __('Published'),
  url: __('URL'),
};

export const comparisonFilters = [
  { key: 'all', label: __('All') },
  { key: 'new', label: __('New') },
  { key: 'resolved', label: __('Resolved') },
  { key: 'updated', label: __('Updated') },
  { key: 'unchanged', label: __('Unchanged') },
];
export const comparisonColumns = [
  { key: 'status', label: __('Status') },
  { key: 'id', label: __('CVE') },
  { key: 'name', label: __('Package') },
  { key: 'severity', label: __('Severity') },
  { key: 'version', label: __('Version') },
  { key: 'fixed', label: __('Fixed') },
  { key: 'scan_status', label: __('Scan status') },
  { key: 'diff', label: __('Diff') },
  { key: 'published', label: __('Published') },
  { key: 'title', label: __('Title') },
];
export const comparisonStatusLabels = {
  new: __('New'),
  resolved: __('Resolved'),
  updated: __('Updated'),
  unchanged: __('Unchanged'),
};

export const severityRank = sev =>
  SEVERITY_RANK[(sev || '').toUpperCase()] || 0;

export const riskLevelFromWorst = worst => {
  if (['critical', 'high'].includes(worst)) return 'high';
  if (worst === 'medium') return 'medium';
  if (worst === 'low') return 'low';
  return 'none';
};

export const formatDateTime = value => {
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
    d.getHours()
  )}:${pad(d.getMinutes())}`;
};

export const compareStrings = (a, b) =>
  (a || '').toString().localeCompare((b || '').toString());

export const normalizeSearchInputValue = (value, event) => {
  if (typeof value === 'string') return value;
  if (typeof event === 'string') return event;
  return value?.target?.value || event?.target?.value || '';
};

export const findingMatchesSearch = (finding, query) =>
  [
    finding.id,
    finding.name,
    finding.version,
    finding.fixed,
    finding.status,
    finding.title,
    finding.url,
    finding.severity,
    katelloFixLabel(finding.katello_fix),
    katelloFixTitle(finding.katello_fix),
  ].some(value =>
    (value || '')
      .toString()
      .toLowerCase()
      .includes(query)
  );

export const findingIdentity = finding =>
  [finding.id, finding.name].map(value => value || '').join('::');

export const findingSorters = {
  published: (a, b) => new Date(a.published || 0) - new Date(b.published || 0),
  name: (a, b) => compareStrings(a.name, b.name),
  version: (a, b) => compareStrings(a.version, b.version),
  fixed: (a, b) => compareStrings(a.fixed, b.fixed),
  katello_fix: (a, b) =>
    katelloFixRank(a.katello_fix) - katelloFixRank(b.katello_fix),
  id: (a, b) => compareStrings(a.id, b.id),
  status: (a, b) => compareStrings(a.status, b.status),
  title: (a, b) => compareStrings(a.title, b.title),
  severity: (a, b) => severityRank(a.severity) - severityRank(b.severity),
};

export const comparisonStatusRank = status => COMPARE_STATUS_RANK[status] || 0;

export const comparisonDiffEntries = diff =>
  Object.entries(diff || {}).map(([field, values]) => ({
    field,
    label: COMPARISON_DIFF_LABELS[field] || field,
    oldValue: values.old || '-',
    newValue: values.new || '-',
  }));

export const formatComparisonDiff = diff =>
  comparisonDiffEntries(diff).map(
    entry => `${entry.label}: ${entry.oldValue} -> ${entry.newValue}`
  );

export const comparisonMatchesSearch = (row, query) =>
  [
    row.id,
    row.name,
    row.title,
    row.published,
    row.severity,
    row.version,
    row.fixed,
    row.scan_status,
    row.status,
    ...formatComparisonDiff(row.diff),
  ].some(value =>
    (value || '')
      .toString()
      .toLowerCase()
      .includes(query)
  );

export const comparisonSorters = {
  status: (a, b) =>
    comparisonStatusRank(a.status) - comparisonStatusRank(b.status),
  id: (a, b) => compareStrings(a.id, b.id),
  name: (a, b) => compareStrings(a.name, b.name),
  published: (a, b) => new Date(a.published || 0) - new Date(b.published || 0),
  severity: (a, b) => severityRank(a.severity) - severityRank(b.severity),
  version: (a, b) => compareStrings(a.version, b.version),
  fixed: (a, b) => compareStrings(a.fixed, b.fixed),
  scan_status: (a, b) => compareStrings(a.scan_status, b.scan_status),
  diff: (a, b) =>
    compareStrings(
      formatComparisonDiff(a.diff).join(' '),
      formatComparisonDiff(b.diff).join(' ')
    ),
  title: (a, b) => compareStrings(a.title, b.title),
};

export const noReportsTitle = () => __('No CVE reports for this host');
export const noReportsBody = () => __('Run a CVE scan to see results here.');
export const noFindingsTitle = () => __('No CVEs found');
export const noFindingsBody = () =>
  __('The latest CVE scan found no vulnerabilities for this host.');
export const visibleScanSource = source =>
  (source || '').toLowerCase() === 'rex' ? '' : source || '';
export const formatScanOrigin = (scanner, source, fallback = __('Unknown')) => {
  const scannerLabel = scanner || fallback;
  const visibleSource = visibleScanSource(source);
  return visibleSource ? `${scannerLabel} / ${visibleSource}` : scannerLabel;
};
export const formatScannedAt = value =>
  formatDateTime(value) || __('Unknown time');

export const katelloFixRank = fix =>
  KATELLO_FIX_RANK[(fix?.status || '').toLowerCase()] ?? 0;

export const katelloFixLabel = fix => {
  switch ((fix?.status || '').toLowerCase()) {
    case 'installable':
      return __('Installable');
    case 'applicable':
      return __('Applicable');
    case 'unavailable':
      return __('No managed fix');
    case 'unknown':
      return __('Unknown');
    default:
      return '';
  }
};

export const katelloFixTitle = fix => {
  const errataIds = (fix?.errata || [])
    .map(erratum => erratum.errata_id)
    .filter(Boolean)
    .join(', ');

  switch ((fix?.status || '').toLowerCase()) {
    case 'installable':
      return errataIds
        ? `${__(
            'A matching erratum is installable for this host'
          )}: ${errataIds}`
        : __('A matching erratum is installable for this host');
    case 'applicable':
      return errataIds
        ? `${__(
            'A matching erratum applies to this host, but is not installable in the current content'
          )}: ${errataIds}`
        : __(
            'A matching erratum applies to this host, but is not installable in the current content'
          );
    case 'unavailable':
      return __(
        'No matching managed erratum was found for this CVE and package'
      );
    case 'unknown':
      if (fix?.reason === 'missing_cve') {
        return __('This finding has no CVE identifier');
      }
      if (fix?.reason === 'query_failed') {
        return __('Fix availability could not be calculated');
      }
      return __('Fix availability is unknown');
    default:
      return '';
  }
};

export const shouldShowKatelloFixColumn = findings =>
  (findings || []).some(finding => finding.katello_fix);

export const katelloFixCounts = findings =>
  (findings || []).reduce(
    (counts, finding) => {
      const status = (finding.katello_fix?.status || '').toLowerCase();
      if (status === 'installable') counts.installable += 1;
      if (status === 'applicable') counts.applicable += 1;
      return counts;
    },
    { installable: 0, applicable: 0 }
  );

export const katelloFixErrataIds = fix =>
  (fix?.errata || []).map(erratum => erratum.errata_id).filter(Boolean);

export const katelloFixErrataSearch = fix => {
  const errataIds = katelloFixErrataIds(fix);
  if (errataIds.length === 0) return '';
  if (errataIds.length === 1) return `errata_id = ${errataIds[0]}`;
  return `errata_id ^ (${errataIds.join(',')})`;
};

export const katelloFixInstallUrl = ({ hostName, fix }) => {
  if ((fix?.status || '').toLowerCase() !== 'installable') return '';
  const errataSearch = katelloFixErrataSearch(fix);
  if (!hostName || !errataSearch) return '';

  const params = new URLSearchParams();
  params.set('feature', KATELLO_ERRATA_INSTALL_FEATURE);
  params.set('search', `name ^ (${hostName})`);
  params.set(`inputs[${ERRATA_SEARCH_INPUT}]`, errataSearch);
  return `/job_invocations/new?${params.toString()}`;
};

export const katelloFixDetailsUrl = fix => {
  const erratumId = (fix?.errata || [])
    .map(erratum => erratum.id)
    .find(Boolean);
  return erratumId ? `/errata/${erratumId}` : '';
};
