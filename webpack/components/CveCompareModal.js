/* eslint-disable import/no-unresolved */
/* eslint-disable camelcase */
import React, { useEffect, useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import {
  Modal,
  Button,
  Text,
  TextVariants,
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
import {
  comparisonDiffEntries,
  comparisonColumns,
  comparisonFilters,
  comparisonMatchesSearch,
  comparisonSorters,
  comparisonStatusLabels,
  formatDateTime,
} from './cve_helpers';
import './cve_scans.scss';

const CveCompareModal = ({ hostId, isOpen, onClose, scanIds }) => {
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState({
    direction: SortByDirection.desc,
    column: 'status',
  });
  const previousScanId = scanIds[0];
  const currentScanId = scanIds[1];
  const compareUrl =
    isOpen && previousScanId && currentScanId
      ? foremanUrl(
          `/api/v2/hosts/${hostId}/cve_scans/compare?first_id=${previousScanId}&second_id=${currentScanId}`
        )
      : null;
  const compareRequest = useAPI(isOpen ? 'get' : null, compareUrl, {
    key: `CVE_COMPARE_${previousScanId}_${currentScanId}`,
  });

  useEffect(() => {
    if (!isOpen) return;
    setFilter('all');
    setSearch('');
    setSortBy({
      direction: SortByDirection.desc,
      column: 'status',
    });
  }, [currentScanId, isOpen, previousScanId]);

  const comparison = compareRequest.response || {};
  const previousScan = comparison.previous || {};
  const currentScan = comparison.current || {};
  const comparisonRows = useMemo(() => comparison.results || [], [
    comparison.results,
  ]);
  const summary = comparison.summary || {};
  const normalizedSearch = search.trim().toLowerCase();
  const filteredRows = useMemo(() => {
    let rows = comparisonRows;
    if (filter !== 'all') {
      rows = rows.filter(row => row.status === filter);
    }
    if (!normalizedSearch) return rows;
    return rows.filter(row => comparisonMatchesSearch(row, normalizedSearch));
  }, [comparisonRows, filter, normalizedSearch]);
  const sortedRows = useMemo(() => {
    const rows = [...filteredRows];
    const sorter = comparisonSorters[sortBy.column] || comparisonSorters.status;
    rows.sort((a, b) => {
      const result = sorter(a, b);
      return sortBy.direction === SortByDirection.asc ? result : -result;
    });
    return rows;
  }, [filteredRows, sortBy]);

  const status = compareRequest.status || STATUS.PENDING;
  const subtitle =
    previousScan.created_at && currentScan.created_at
      ? `${formatDateTime(previousScan.created_at)} -> ${formatDateTime(
          currentScan.created_at
        )}`
      : __('Compare CVE reports');

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
  const renderDiff = diff => {
    const entries = comparisonDiffEntries(diff);
    if (entries.length === 0) return '-';

    return entries.map(entry => (
      <div key={entry.field} className="cve-compare-diff-entry">
        <span className="cve-compare-diff-label">{entry.label}:</span>{' '}
        <span className="cve-compare-diff-values">
          <span className="cve-compare-diff-old">{entry.oldValue}</span>
          <span className="cve-compare-diff-arrow">-&gt;</span>
          <span className="cve-compare-diff-new">{entry.newValue}</span>
        </span>
      </div>
    ));
  };

  return (
    <Modal
      title={__('Compare CVE reports')}
      description={subtitle}
      isOpen={isOpen}
      onClose={onClose}
      width="80%"
      maxWidth="80%"
      ouiaId="cve-compare-modal"
      actions={[
        <Button
          key="close"
          variant="primary"
          onClick={onClose}
          ouiaId="cve-compare-close"
        >
          {__('Close')}
        </Button>,
      ]}
    >
      {status === STATUS.PENDING ? (
        <Text component={TextVariants.small} ouiaId="cve-compare-loading">
          {__('Loading...')}
        </Text>
      ) : (
        <div className="cve-modal-body cve-compare-body">
          <div className="cve-compare-summary">
            <div className="cve-compare-meta">
              <Text
                component={TextVariants.small}
                ouiaId="cve-compare-previous"
              >
                {__('Previous')}: {previousScan.scanner || __('Unknown')} /{' '}
                {formatDateTime(previousScan.created_at)}
              </Text>
              <Text component={TextVariants.small} ouiaId="cve-compare-current">
                {__('Current')}: {currentScan.scanner || __('Unknown')} /{' '}
                {formatDateTime(currentScan.created_at)}
              </Text>
            </div>
            <div className="cve-compare-cards">
              {comparisonFilters
                .filter(item => item.key !== 'all')
                .map(item => (
                  <button
                    key={item.key}
                    type="button"
                    className={
                      filter === item.key
                        ? 'cve-compare-card is-active'
                        : 'cve-compare-card'
                    }
                    onClick={() => setFilter(item.key)}
                  >
                    <span className="cve-compare-card-label">{item.label}</span>
                    <span className="cve-compare-card-value">
                      {summary[item.key]}
                    </span>
                  </button>
                ))}
            </div>
          </div>

          <div className="cve-modal-filters">
            <SearchInput
              id="cve-compare-search"
              value={search}
              onChange={onSearchChange}
              onClear={() => setSearch('')}
              onSearch={onSearchChange}
              placeholder={__('Search comparison by CVE, package, diff...')}
              aria-label={__('Search CVE comparison')}
              className="cve-modal-search"
            />
            <div className="cve-modal-quick-filters">
              <div className="cve-filter-buttons">
                {comparisonFilters.map(item => (
                  <button
                    key={item.key}
                    type="button"
                    aria-pressed={filter === item.key}
                    className={
                      filter === item.key
                        ? 'cve-filter-button is-active'
                        : 'cve-filter-button'
                    }
                    onClick={() => setFilter(item.key)}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="cve-modal-results">
            {sortedRows.length === 0 ? (
              <Text component={TextVariants.small} ouiaId="cve-compare-empty">
                {__('No CVE differences match the selected filters')}
              </Text>
            ) : (
              <Table
                variant="compact"
                aria-label="CVE comparison table"
                ouiaId="cve-compare-table"
              >
                <Thead>
                  <Tr ouiaId="cve-compare-header">
                    {comparisonColumns.map(column => (
                      <Th
                        key={column.key}
                        className="cve-sortable"
                        onClick={() => onSort(column.key)}
                      >
                        {column.label}
                      </Th>
                    ))}
                  </Tr>
                </Thead>
                <Tbody>
                  {sortedRows.map((row, index) => (
                    <Tr key={row.key} ouiaId={`cve-compare-row-${index}`}>
                      <Td dataLabel={__('Status')}>
                        {comparisonStatusLabels[row.status]}
                      </Td>
                      <Td dataLabel={__('CVE')}>
                        {row.url ? (
                          <a href={row.url} target="_blank" rel="noreferrer">
                            {row.id}
                          </a>
                        ) : (
                          row.id
                        )}
                      </Td>
                      <Td dataLabel={__('Package')}>{row.name}</Td>
                      <Td dataLabel={__('Severity')}>{row.severity}</Td>
                      <Td dataLabel={__('Version')}>{row.version}</Td>
                      <Td dataLabel={__('Fixed')}>{row.fixed}</Td>
                      <Td dataLabel={__('Scan status')}>{row.scan_status}</Td>
                      <Td dataLabel={__('Diff')}>{renderDiff(row.diff)}</Td>
                      <Td dataLabel={__('Published')}>
                        {formatDateTime(row.published)}
                      </Td>
                      <Td dataLabel={__('Title')} title={row.title}>
                        <span className="cve-truncate">{row.title}</span>
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            )}
          </div>
        </div>
      )}
    </Modal>
  );
};

CveCompareModal.propTypes = {
  hostId: PropTypes.number.isRequired,
  isOpen: PropTypes.bool.isRequired,
  onClose: PropTypes.func.isRequired,
  scanIds: PropTypes.arrayOf(PropTypes.number),
};

CveCompareModal.defaultProps = {
  scanIds: [],
};

export default CveCompareModal;
