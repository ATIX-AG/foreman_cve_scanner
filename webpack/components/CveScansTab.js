/* eslint-disable import/no-unresolved */
import React, { useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import {
  Button,
  Checkbox,
  Pagination,
  EmptyState,
  EmptyStateIcon,
  EmptyStateBody,
  Title,
} from '@patternfly/react-core';
import { SearchIcon } from '@patternfly/react-icons';
import { Table, Thead, Tbody, Tr, Th, Td } from '@patternfly/react-table';
import { useAPI } from 'foremanReact/common/hooks/API/APIHooks';
import { foremanUrl } from 'foremanReact/common/helpers';
import { translate as __ } from 'foremanReact/common/I18n';
import SkeletonLoader from 'foremanReact/components/common/SkeletonLoader';
import { STATUS } from 'foremanReact/constants';
import RelativeDateTime from 'foremanReact/components/common/dates/RelativeDateTime';
import CveTrendChart from './CveTrendChart';
import CveFindingsModal from './CveFindingsModal';
import CveCompareModal from './CveCompareModal';
import { noReportsBody, noReportsTitle } from './cve_helpers';
import './cve_scans.scss';

const DEFAULT_PER_PAGE = 20;

const CveScansTab = ({ response }) => {
  const hostId = response?.id;
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(DEFAULT_PER_PAGE);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isCompareOpen, setIsCompareOpen] = useState(false);
  const [modalScanId, setModalScanId] = useState(null);
  const [modalFilter, setModalFilter] = useState('all');
  const [selectedScanIds, setSelectedScanIds] = useState([]);

  const historyUrl = hostId
    ? foremanUrl(
        `/api/v2/hosts/${hostId}/cve_scans?page=${page}&per_page=${perPage}`
      )
    : null;
  const { response: apiResponse, status } = useAPI('get', historyUrl, {
    key: `CVE_SCANS_TAB_${hostId}_${page}_${perPage}`,
  });

  const scans = useMemo(() => apiResponse?.results || [], [apiResponse]);
  const selectedScans = useMemo(
    () => scans.filter(scan => selectedScanIds.includes(scan.id)),
    [scans, selectedScanIds]
  );
  const orderedCompareIds = useMemo(
    () =>
      [...selectedScans]
        .sort(
          (a, b) =>
            new Date(a.created_at || 0).getTime() -
            new Date(b.created_at || 0).getTime()
        )
        .map(scan => scan.id),
    [selectedScans]
  );
  const itemCount = apiResponse?.total ?? scans.length;
  if (!hostId) return null;

  const openModal = (scanId, filter) => {
    setModalScanId(scanId);
    setModalFilter(filter || 'all');
    setIsModalOpen(true);
  };
  const exportUrlFor = scanId =>
    foremanUrl(`/api/v2/hosts/${hostId}/cve_scans/${scanId}/export`);

  const onSetPage = (_event, newPage) => {
    setPage(newPage);
    setSelectedScanIds([]);
  };
  const onPerPageSelect = (_event, newPerPage) => {
    setPerPage(newPerPage);
    setPage(1);
    setSelectedScanIds([]);
  };
  const toggleScanSelection = scanId => {
    setSelectedScanIds(currentSelection => {
      if (currentSelection.includes(scanId)) {
        return currentSelection.filter(id => id !== scanId);
      }
      if (currentSelection.length >= 2) return currentSelection;
      return [...currentSelection, scanId];
    });
  };
  const clearSelection = () => setSelectedScanIds([]);

  return (
    <div className="cve-scans-tab">
      <SkeletonLoader status={status || STATUS.PENDING}>
        {scans.length === 0 ? (
          <EmptyState>
            <EmptyStateIcon icon={SearchIcon} />
            <Title headingLevel="h4" size="md" ouiaId="cve-scans-empty-title">
              {noReportsTitle()}
            </Title>
            <EmptyStateBody>{noReportsBody()}</EmptyStateBody>
          </EmptyState>
        ) : (
          <>
            <CveTrendChart scans={scans} onOpen={scanId => openModal(scanId, 'all')} />
            <div className="cve-scans-toolbar">
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
              <div className="cve-scans-actions">
                <span className="cve-scans-selection">
                  {__('Selected')}: {selectedScans.length}/2
                </span>
                <Button
                  variant="secondary"
                  isDisabled={selectedScans.length !== 2}
                  onClick={() => setIsCompareOpen(true)}
                  ouiaId="cve-scans-compare"
                >
                  {__('Compare selected')}
                </Button>
                <Button
                  variant="link"
                  isDisabled={selectedScans.length === 0}
                  onClick={clearSelection}
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
                  <Th>{__('Reported at')}</Th>
                  <Th>{__('Scanner')}</Th>
                  <Th>{__('Total')}</Th>
                  <Th>{__('Critical')}</Th>
                  <Th>{__('High')}</Th>
                  <Th>{__('Medium')}</Th>
                  <Th>{__('Low')}</Th>
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
                        onChange={() => toggleScanSelection(scan.id)}
                        aria-label={__('Select scan for comparison')}
                      />
                    </Td>
                    <Td dataLabel={__('Reported at')}>
                      <Button
                        variant="link"
                        className="cve-summary-link"
                        onClick={() => openModal(scan.id, 'all')}
                        ouiaId={`cve-scans-open-${scan.id}`}
                      >
                        <RelativeDateTime
                          date={scan.created_at}
                          defaultValue={__('Unknown time')}
                        />
                      </Button>
                    </Td>
                    <Td dataLabel={__('Scanner')}>{scan.scanner}</Td>
                    <Td dataLabel={__('Total')}>
                      <Button
                        variant="link"
                        className="cve-summary-link"
                        onClick={() => openModal(scan.id, 'all')}
                        ouiaId={`cve-scans-total-${scan.id}`}
                      >
                        {scan.total}
                      </Button>
                    </Td>
                    <Td dataLabel={__('Critical')}>
                      <Button
                        variant="link"
                        className="cve-summary-link"
                        onClick={() => openModal(scan.id, 'critical')}
                        ouiaId={`cve-scans-critical-${scan.id}`}
                      >
                        {scan.critical}
                      </Button>
                    </Td>
                    <Td dataLabel={__('High')}>
                      <Button
                        variant="link"
                        className="cve-summary-link"
                        onClick={() => openModal(scan.id, 'high')}
                        ouiaId={`cve-scans-high-${scan.id}`}
                      >
                        {scan.high}
                      </Button>
                    </Td>
                    <Td dataLabel={__('Medium')}>
                      <Button
                        variant="link"
                        className="cve-summary-link"
                        onClick={() => openModal(scan.id, 'medium')}
                        ouiaId={`cve-scans-medium-${scan.id}`}
                      >
                        {scan.medium}
                      </Button>
                    </Td>
                    <Td dataLabel={__('Low')}>
                      <Button
                        variant="link"
                        className="cve-summary-link"
                        onClick={() => openModal(scan.id, 'low')}
                        ouiaId={`cve-scans-low-${scan.id}`}
                      >
                        {scan.low}
                      </Button>
                    </Td>
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
          </>
        )}
      </SkeletonLoader>
      <CveFindingsModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        hostId={hostId}
        scanId={modalScanId}
        initialFilter={modalFilter}
      />
      <CveCompareModal
        isOpen={isCompareOpen}
        onClose={() => setIsCompareOpen(false)}
        hostId={hostId}
        scanIds={orderedCompareIds}
      />
    </div>
  );
};

CveScansTab.propTypes = {
  response: PropTypes.shape({
    id: PropTypes.number,
  }),
};

CveScansTab.defaultProps = {
  response: undefined,
};

export default CveScansTab;
