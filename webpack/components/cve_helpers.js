/* eslint-disable import/no-unresolved */
import { translate as __ } from 'foremanReact/common/I18n';

const SEVERITY_RANK = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};
const COMPARE_STATUS_RANK = {
  new: 5,
  resolved: 4,
  severity_changed: 3,
  updated: 2,
  unchanged: 1,
};
export const comparisonFilters = [
  { key: 'all_changes', label: __('All changes') },
  { key: 'new', label: __('New') },
  { key: 'resolved', label: __('Resolved') },
  { key: 'severity_changed', label: __('Severity changed') },
  { key: 'updated', label: __('Updated') },
  { key: 'unchanged', label: __('Unchanged') },
];
export const comparisonColumns = [
  { key: 'status', label: __('Status') },
  { key: 'id', label: __('CVE') },
  { key: 'name', label: __('Package') },
  { key: 'oldSeverity', label: __('Old severity') },
  { key: 'newSeverity', label: __('New severity') },
  { key: 'oldVersion', label: __('Old version') },
  { key: 'newVersion', label: __('New version') },
  { key: 'published', label: __('Published') },
  { key: 'title', label: __('Title') },
];
export const comparisonStatusLabels = {
  new: __('New'),
  resolved: __('Resolved'),
  severity_changed: __('Severity changed'),
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

const findingIdentity = finding => `${finding.id || ''}::${finding.name || ''}`;
const normalizeStatus = status => status || 'open';

const compareFindingPayload = (previousFinding, currentFinding) =>
  ['version', 'fixed', 'status', 'title', 'url', 'published'].some(
    key => (previousFinding?.[key] || '') !== (currentFinding?.[key] || '')
  );

const comparisonStatusFor = (previousFinding, currentFinding) => {
  if (!previousFinding) return 'new';
  if (!currentFinding) return 'resolved';
  if ((previousFinding.severity || '') !== (currentFinding.severity || '')) {
    return 'severity_changed';
  }
  if (compareFindingPayload(previousFinding, currentFinding)) return 'updated';
  return 'unchanged';
};

export const comparisonStatusRank = status => COMPARE_STATUS_RANK[status] || 0;

export const compareScanFindings = (
  previousFindings = [],
  currentFindings = []
) => {
  const previousMap = new Map(
    previousFindings.map(finding => [findingIdentity(finding), finding])
  );
  const currentMap = new Map(
    currentFindings.map(finding => [findingIdentity(finding), finding])
  );
  const identities = Array.from(
    new Set([...previousMap.keys(), ...currentMap.keys()])
  );

  return identities.map(identity => {
    const previousFinding = previousMap.get(identity);
    const currentFinding = currentMap.get(identity);
    return {
      key: identity,
      status: comparisonStatusFor(previousFinding, currentFinding),
      id: currentFinding?.id || previousFinding?.id,
      name: currentFinding?.name || previousFinding?.name,
      title: currentFinding?.title || previousFinding?.title,
      published: currentFinding?.published || previousFinding?.published,
      oldSeverity: previousFinding?.severity || '',
      newSeverity: currentFinding?.severity || '',
      oldVersion: previousFinding?.version || '',
      newVersion: currentFinding?.version || '',
      oldFixed: previousFinding?.fixed || '',
      newFixed: currentFinding?.fixed || '',
      oldStatus: normalizeStatus(previousFinding?.status),
      newStatus: normalizeStatus(currentFinding?.status),
      url: currentFinding?.url || previousFinding?.url,
    };
  });
};

export const summarizeComparison = rows =>
  rows.reduce(
    (summary, row) => {
      summary[row.status] += 1;
      return summary;
    },
    {
      new: 0,
      resolved: 0,
      severity_changed: 0,
      updated: 0,
      unchanged: 0,
    }
  );

export const comparisonMatchesSearch = (row, query) =>
  [
    row.id,
    row.name,
    row.title,
    row.published,
    row.oldSeverity,
    row.newSeverity,
    row.oldVersion,
    row.newVersion,
    row.oldFixed,
    row.newFixed,
    row.oldStatus,
    row.newStatus,
    row.status,
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
  oldSeverity: (a, b) =>
    severityRank(a.oldSeverity) - severityRank(b.oldSeverity),
  newSeverity: (a, b) =>
    severityRank(a.newSeverity) - severityRank(b.newSeverity),
  oldVersion: (a, b) => compareStrings(a.oldVersion, b.oldVersion),
  newVersion: (a, b) => compareStrings(a.newVersion, b.newVersion),
};

export const noReportsTitle = () => __('No CVE reports for this host');
export const noReportsBody = () => __('Run a CVE scan to see results here.');
