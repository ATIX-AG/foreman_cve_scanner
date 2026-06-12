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
