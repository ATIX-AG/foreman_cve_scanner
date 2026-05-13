/* eslint-disable import/no-unresolved */
/* eslint-disable camelcase */
import React, { useEffect, useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import {
  Modal,
  Button,
  Text,
  TextVariants,
  FormGroup,
  SearchInput,
} from '@patternfly/react-core';
import {
  Table,
  Tbody,
  Tr,
  Th,
  Thead,
  Td,
  SortByDirection,
} from '@patternfly/react-table';
import { useAPI } from 'foremanReact/common/hooks/API/APIHooks';
import { foremanUrl } from 'foremanReact/common/helpers';
import { translate as __ } from 'foremanReact/common/I18n';
import { STATUS } from 'foremanReact/constants';
import SeverityIcon from './SeverityIcon';
import { compareStrings, formatDateTime, severityRank } from './cve_helpers';
import './cve_scans.scss';

const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low'];
const COLUMNS = [
  { key: 'severity', label: __('Severity') },
  { key: 'published', label: __('Published') },
  { key: 'name', label: __('Package') },
  { key: 'version', label: __('Affected version') },
  { key: 'fixed', label: __('Fixed version') },
  { key: 'status', label: __('Status') },
  { key: 'id', label: __('CVE') },
  { key: 'title', label: __('Title') },
];

const CveFindingsModal = ({
  isOpen,
  onClose,
  hostId,
  scanId,
  initialFilter,
}) => {
  const [filter, setFilter] = useState(initialFilter || 'all');
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState({
    direction: SortByDirection.desc,
    column: 'severity',
  });
  const normalizedScanId =
    scanId !== null && scanId !== undefined && String(scanId).trim() !== ''
      ? scanId
      : null;
  const url = normalizedScanId
    ? foremanUrl(`/api/v2/hosts/${hostId}/cve_scans/${normalizedScanId}`)
    : foremanUrl(`/api/v2/hosts/${hostId}/cve_scans/latest`);

  const { response, status } = useAPI(isOpen ? 'get' : null, url, {
    key: `CVE_SCAN_${normalizedScanId || 'latest'}`,
  });

  useEffect(() => {
    if (!isOpen) return;
    setFilter(initialFilter || 'all');
    setSearch('');
  }, [initialFilter, isOpen, scanId]);

  const payload = response || {};
  const findings = Array.isArray(payload.findings) ? payload.findings : [];

  const normalizedFilter = (filter || 'all').toLowerCase();
  const filteredFindings = useMemo(() => {
    if (normalizedFilter === 'all') return findings;
    return findings.filter(
      f => (f.severity || '').toLowerCase() === normalizedFilter
    );
  }, [normalizedFilter, findings]);
  const normalizedSearch = search.trim().toLowerCase();
  const visibleFindings = useMemo(() => {
    if (!normalizedSearch) return filteredFindings;
    return filteredFindings.filter(finding =>
      [
        finding.id,
        finding.name,
        finding.version,
        finding.fixed,
        finding.status,
        finding.title,
        finding.url,
        finding.severity,
      ]
        .some(value =>
          (value || '').toString().toLowerCase().includes(normalizedSearch)
        )
    );
  }, [filteredFindings, normalizedSearch]);

  const formatPublished = formatDateTime;

  const sorters = useMemo(
    () => ({
      published: (a, b) =>
        new Date(a.published || 0) - new Date(b.published || 0),
      name: (a, b) => compareStrings(a.name, b.name),
      version: (a, b) => compareStrings(a.version, b.version),
      fixed: (a, b) => compareStrings(a.fixed, b.fixed),
      id: (a, b) => compareStrings(a.id, b.id),
      status: (a, b) => compareStrings(a.status, b.status),
      title: (a, b) => compareStrings(a.title, b.title),
      severity: (a, b) => severityRank(a.severity) - severityRank(b.severity),
    }),
    []
  );
  const sortedFindings = useMemo(() => {
    const list = [...visibleFindings];
    const sortKey = sortBy.column || 'severity';
    const sorter = sorters[sortKey] || sorters.severity;
    list.sort((a, b) => {
      const result = sorter(a, b);
      return sortBy.direction === SortByDirection.asc ? result : -result;
    });
    return list;
  }, [visibleFindings, sortBy, sorters]);

  const onSort = column => {
    const nextDirection =
      sortBy.column === column && sortBy.direction === SortByDirection.asc
        ? SortByDirection.desc
        : SortByDirection.asc;
    setSortBy({ column, direction: nextDirection });
  };
  const onSearchChange = (value, event) => {
    if (typeof value === 'string') {
      setSearch(value);
      return;
    }
    if (typeof event === 'string') {
      setSearch(event);
      return;
    }
    setSearch(value?.target?.value || event?.target?.value || '');
  };

  return (
    <Modal
      title={
        payload?.created_at && typeof payload?.total !== 'undefined'
          ? `${__('Report from')} ${formatPublished(payload.created_at)} - ${__(
              'Total'
            )}: ${payload.total}`
          : __('CVE findings')
      }
      isOpen={isOpen}
      onClose={onClose}
      width="70%"
      maxWidth="70%"
      ouiaId="cve-findings-modal"
      actions={[
        <Button
          key="close"
          variant="primary"
          onClick={onClose}
          ouiaId="cve-findings-close"
        >
          {__('Close')}
        </Button>,
      ]}
    >
      {status === STATUS.PENDING ? (
        <Text component={TextVariants.small} ouiaId="cve-findings-loading">
          {__('Loading...')}
        </Text>
      ) : (
        <div className="cve-modal-body">
          <div className="cve-modal-filters">
            <FormGroup fieldId="cve-search" className="cve-modal-search">
              <SearchInput
                id="cve-search"
                value={search}
                onChange={onSearchChange}
                onClear={() => setSearch('')}
                onSearch={onSearchChange}
                placeholder={__('Search CVE, package, status, title...')}
                aria-label={__('Search CVE report')}
              />
            </FormGroup>
            <FormGroup fieldId="cve-filter" className="cve-modal-quick-filters">
              <div className="cve-filter-buttons">
                {SEVERITY_OPTIONS.map(opt => (
                  <button
                    key={opt}
                    type="button"
                    aria-pressed={filter === opt}
                    className={
                      filter === opt
                        ? 'cve-filter-button is-active'
                        : 'cve-filter-button'
                    }
                    onClick={() => setFilter(opt)}
                  >
                    {__(opt)}
                  </button>
                ))}
              </div>
            </FormGroup>
          </div>

          {response?.error && (
            <Text component={TextVariants.small} ouiaId="cve-findings-error">
              {response.error.message}
            </Text>
          )}
          {sortedFindings.length === 0 && !response?.error ? (
            <Text component={TextVariants.small} ouiaId="cve-findings-empty">
              {__('No findings for selected filter')}
            </Text>
          ) : (
            <Table
              variant="compact"
              aria-label="CVE findings table"
              ouiaId="cve-findings-table"
            >
              <Thead>
                <Tr ouiaId="cve-findings-header">
                  {COLUMNS.map(col => (
                    <Th
                      key={col.key}
                      className={`cve-col-${col.key} cve-sortable`}
                      aria-label={
                        col.key === 'severity' ? __('Severity') : undefined
                      }
                      onClick={() => onSort(col.key)}
                    >
                      {col.key === 'severity' ? (
                        <SeverityIcon severity="high" />
                      ) : (
                        col.label
                      )}
                      {sortBy.column === col.key && (
                        <span className="cve-sort-indicator">
                          {sortBy.direction === SortByDirection.asc
                            ? ' ▲'
                            : ' ▼'}
                        </span>
                      )}
                    </Th>
                  ))}
                </Tr>
              </Thead>
              <Tbody>
                {sortedFindings.map((finding, index) => (
                  <Tr key={finding.id} ouiaId={`cve-findings-row-${index}`}>
                    <Td dataLabel={__('Severity')}>
                      <span
                        className="cve-summary cve-summary--icon-only"
                        title={finding.severity}
                        aria-label={finding.severity}
                      >
                        <SeverityIcon
                          severity={(finding.severity || '').toLowerCase()}
                        />
                      </span>
                    </Td>
                    <Td dataLabel={__('Published')}>
                      {formatPublished(finding.published)}
                    </Td>
                    <Td dataLabel={__('Package')}>{finding.name}</Td>
                    <Td dataLabel={__('Affected version')}>
                      {finding.version}
                    </Td>
                    <Td dataLabel={__('Fixed version')} title={finding.fixed}>
                      <span className="cve-truncate">{finding.fixed}</span>
                    </Td>
                    <Td dataLabel={__('Status')}>
                      {finding.status || __('open')}
                    </Td>
                    <Td dataLabel={__('CVE')}>
                      {finding.url ? (
                        <a href={finding.url} target="_blank" rel="noreferrer">
                          {finding.id}
                        </a>
                      ) : (
                        finding.id
                      )}
                    </Td>
                    <Td dataLabel={__('Title')} title={finding.title}>
                      <span className="cve-truncate">{finding.title}</span>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )}
        </div>
      )}
    </Modal>
  );
};

CveFindingsModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  onClose: PropTypes.func.isRequired,
  hostId: PropTypes.number.isRequired,
  scanId: PropTypes.number,
  initialFilter: PropTypes.string,
};

CveFindingsModal.defaultProps = {
  scanId: undefined,
  initialFilter: 'all',
};

export default CveFindingsModal;
