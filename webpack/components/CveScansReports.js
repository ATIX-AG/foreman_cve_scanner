/* eslint-disable import/no-unresolved */
import React from 'react';
import PropTypes from 'prop-types';
import { Button, Checkbox, Pagination, Title } from '@patternfly/react-core';
import { Table, Thead, Tbody, Tr, Th, Td } from '@patternfly/react-table';
import { translate as __ } from 'foremanReact/common/I18n';
import RelativeDateTime from 'foremanReact/components/common/dates/RelativeDateTime';
import { formatScanOrigin } from './cve_helpers';

const SCAN_COUNT_COLUMNS = [
  { key: 'total', label: __('Total'), filter: 'all' },
  { key: 'critical', label: __('Critical'), filter: 'critical' },
  { key: 'high', label: __('High'), filter: 'high' },
  { key: 'medium', label: __('Medium'), filter: 'medium' },
  { key: 'low', label: __('Low'), filter: 'low' },
];

const CveScansReports = ({
  scans,
  itemCount,
  page,
  perPage,
  onSetPage,
  onPerPageSelect,
  selectedScanIds,
  selectedCount,
  onCompare,
  onClearSelection,
  onToggleSelection,
  onOpenModal,
  exportUrlFor,
}) => (
  <section className="cve-scans-section" aria-label="CVE scan reports">
    <div className="cve-scans-section-header">
      <div className="cve-scans-section-title">
        <Title headingLevel="h3" size="lg" ouiaId="cve-scans-reports-title">
          {__('Reports')}
        </Title>
      </div>
      <Pagination
        itemCount={itemCount}
        perPage={perPage}
        page={page}
        onSetPage={onSetPage}
        onPerPageSelect={onPerPageSelect}
        variant="top"
        isCompact
        ouiaId="cve-scans-pagination"
      />
    </div>
    <div className="cve-scans-toolbar">
      <div className="cve-scans-actions">
        <span className="cve-scans-selection">
          {__('Selected')}: {selectedCount}/2
        </span>
        <Button
          variant="secondary"
          isDisabled={selectedCount !== 2}
          onClick={onCompare}
          ouiaId="cve-scans-compare"
        >
          {__('Compare selected')}
        </Button>
        <Button
          variant="link"
          isDisabled={selectedCount === 0}
          onClick={onClearSelection}
          ouiaId="cve-scans-clear-selection"
        >
          {__('Clear selection')}
        </Button>
      </div>
    </div>
    <Table
      variant="compact"
      aria-label="CVE scans history"
      ouiaId="cve-scans-table"
    >
      <Thead>
        <Tr ouiaId="cve-scans-header">
          <Th>{__('Select')}</Th>
          <Th>{__('Scanned at')}</Th>
          <Th>{__('Scanner')}</Th>
          {SCAN_COUNT_COLUMNS.map(column => (
            <Th key={column.key}>{column.label}</Th>
          ))}
          <Th>{__('Export')}</Th>
        </Tr>
      </Thead>
      <Tbody>
        {scans.map((scan, index) => (
          <Tr key={scan.id} ouiaId={`cve-scans-row-${index}`}>
            <Td dataLabel={__('Select')}>
              <Checkbox
                id={`cve-scan-select-${scan.id}`}
                isChecked={selectedScanIds.includes(scan.id)}
                isDisabled={
                  selectedScanIds.length === 2 &&
                  !selectedScanIds.includes(scan.id)
                }
                onChange={() => onToggleSelection(scan.id)}
                aria-label={__('Select scan for comparison')}
                ouiaId={`cve-scan-select-${scan.id}`}
              />
            </Td>
            <Td dataLabel={__('Scanned at')}>
              <Button
                variant="link"
                className="cve-summary-link"
                onClick={() => onOpenModal(scan.id, 'all')}
                ouiaId={`cve-scans-open-${scan.id}`}
              >
                <RelativeDateTime
                  date={scan.scanned_at}
                  defaultValue={__('Unknown time')}
                />
              </Button>
            </Td>
            <Td dataLabel={__('Scanner')}>
              {formatScanOrigin(scan.scanner, scan.source)}
            </Td>
            {SCAN_COUNT_COLUMNS.map(column => (
              <Td key={column.key} dataLabel={column.label}>
                <Button
                  variant="link"
                  className="cve-summary-link"
                  onClick={() => onOpenModal(scan.id, column.filter)}
                  ouiaId={`cve-scans-${column.key}-${scan.id}`}
                >
                  {scan[column.key]}
                </Button>
              </Td>
            ))}
            <Td dataLabel={__('Export')}>
              <Button
                component="a"
                variant="secondary"
                href={exportUrlFor(scan.id)}
                ouiaId={`cve-scans-export-${scan.id}`}
              >
                {__('Export CSV')}
              </Button>
            </Td>
          </Tr>
        ))}
      </Tbody>
    </Table>
  </section>
);

CveScansReports.propTypes = {
  scans: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.number.isRequired,
      scanned_at: PropTypes.string,
      scanner: PropTypes.string,
      source: PropTypes.string,
      total: PropTypes.number,
      critical: PropTypes.number,
      high: PropTypes.number,
      medium: PropTypes.number,
      low: PropTypes.number,
    })
  ),
  itemCount: PropTypes.number,
  page: PropTypes.number,
  perPage: PropTypes.number,
  onSetPage: PropTypes.func,
  onPerPageSelect: PropTypes.func,
  selectedScanIds: PropTypes.arrayOf(PropTypes.number),
  selectedCount: PropTypes.number,
  onCompare: PropTypes.func,
  onClearSelection: PropTypes.func,
  onToggleSelection: PropTypes.func,
  onOpenModal: PropTypes.func,
  exportUrlFor: PropTypes.func,
};

CveScansReports.defaultProps = {
  scans: [],
  itemCount: 0,
  page: 1,
  perPage: 20,
  onSetPage: () => {},
  onPerPageSelect: () => {},
  selectedScanIds: [],
  selectedCount: 0,
  onCompare: () => {},
  onClearSelection: () => {},
  onToggleSelection: () => {},
  onOpenModal: () => {},
  exportUrlFor: () => '#',
};

export default CveScansReports;
