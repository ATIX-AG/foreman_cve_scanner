/* eslint-disable import/no-unresolved */
import { translate as __ } from 'foremanReact/common/I18n';

const SEVERITY_RANK = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
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

export const noReportsTitle = () => __('No CVE reports for this host');
export const noReportsBody = () => __('Run a CVE scan to see results here.');
