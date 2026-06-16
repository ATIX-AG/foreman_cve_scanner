/* eslint-disable import/no-unresolved */
/* eslint-disable camelcase */
import React, { useEffect, useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import {
  EmptyState,
  EmptyStateBody,
  EmptyStateIcon,
  FormGroup,
  SearchInput,
  Text,
  TextContent,
  TextVariants,
  Title,
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
import { CheckCircleIcon, SearchIcon } from '@patternfly/react-icons';
import { translate as __ } from 'foremanReact/common/I18n';
import { STATUS } from 'foremanReact/constants';
import SeverityIcon from './SeverityIcon';
import CveLink from './CveLink';
import useSortBy from './useSortBy';
import {
  findingIdentity,
  findingMatchesSearch,
  findingSorters,
  formatDateTime,
  formatScanOrigin,
  formatScannedAt,
  noFindingsBody,
  noFindingsTitle,
  noReportsBody,
  noReportsTitle,
  normalizeSearchInputValue,
} from './cve_helpers';
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

const CveFindingsView = ({ scan, status, initialFilter }) => {
  const [filter, setFilter] = useState(initialFilter || 'all');
  const [search, setSearch] = useState('');
  const scanId = scan?.id;
  const findings = Array.isArray(scan?.findings) ? scan.findings : [];
  const origin = formatScanOrigin(scan?.scanner, scan?.source);
  const normalizedFilter = (filter || 'all').toLowerCase();
  const filteredFindings =
    normalizedFilter === 'all'
      ? findings
      : findings.filter(
          finding => (finding.severity || '').toLowerCase() === normalizedFilter
        );
  const normalizedSearch = search.trim().toLowerCase();
  const visibleFindings = useMemo(() => {
    if (!normalizedSearch) return filteredFindings;
    return filteredFindings.filter(finding =>
      findingMatchesSearch(finding, normalizedSearch)
    );
  }, [filteredFindings, normalizedSearch]);
  const { sortBy, onSort, sortedItems: sortedFindings } = useSortBy(
    'severity',
    findingSorters,
    visibleFindings
  );

  useEffect(() => {
    setFilter(initialFilter || 'all');
    setSearch('');
  }, [initialFilter, scanId]);

  if (status === STATUS.PENDING) {
    return (
      <Text component={TextVariants.small} ouiaId="cve-findings-loading">
        {__('Loading...')}
      </Text>
    );
  }

  if (scan?.error) {
    return (
      <Text component={TextVariants.small} ouiaId="cve-findings-error">
        {scan.error.message}
      </Text>
    );
  }

  if (!scan?.id) {
    return (
      <EmptyState>
        <EmptyStateIcon icon={SearchIcon} />
        <Title headingLevel="h4" size="md" ouiaId="cve-findings-empty-title">
          {noReportsTitle()}
        </Title>
        <EmptyStateBody>{noReportsBody()}</EmptyStateBody>
      </EmptyState>
    );
  }

  const onSearchChange = (value, event) => {
    setSearch(normalizeSearchInputValue(value, event));
  };

  return (
    <div className="cve-modal-body">
      <TextContent className="cve-findings-meta">
        <Text component={TextVariants.small} ouiaId="cve-findings-summary">
          {`${__('Report from')} ${formatScannedAt(
            scan.scanned_at
          )} - ${origin} - ${__('Total')}: ${scan.total}`}
        </Text>
      </TextContent>

      {findings.length === 0 ? (
        <EmptyState className="cve-empty-state cve-empty-state--success">
          <EmptyStateIcon icon={CheckCircleIcon} />
          <Title headingLevel="h4" size="md" ouiaId="cve-findings-clean-title">
            {noFindingsTitle()}
          </Title>
          <EmptyStateBody>{noFindingsBody()}</EmptyStateBody>
        </EmptyState>
      ) : (
        <>
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

          <div className="cve-modal-results">
            {sortedFindings.length === 0 ? (
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
                    <Tr
                      key={findingIdentity(finding)}
                      ouiaId={`cve-findings-row-${index}`}
                    >
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
                        {formatDateTime(finding.published)}
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
                        <CveLink id={finding.id} url={finding.url} />
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
        </>
      )}
    </div>
  );
};

CveFindingsView.propTypes = {
  scan: PropTypes.shape({
    id: PropTypes.number,
    scanned_at: PropTypes.string,
    scanner: PropTypes.string,
    source: PropTypes.string,
    total: PropTypes.number,
    findings: PropTypes.arrayOf(PropTypes.object),
    error: PropTypes.shape({
      message: PropTypes.string,
    }),
  }),
  status: PropTypes.string,
  initialFilter: PropTypes.string,
};

CveFindingsView.defaultProps = {
  scan: undefined,
  status: undefined,
  initialFilter: 'all',
};

export default CveFindingsView;
