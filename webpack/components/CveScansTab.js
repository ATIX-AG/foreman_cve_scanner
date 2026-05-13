/* eslint-disable import/no-unresolved */
import React, { useEffect, useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import {
  EmptyState,
  EmptyStateIcon,
  EmptyStateBody,
  Tab,
  TabTitleText,
  Tabs,
  Title,
} from '@patternfly/react-core';
import { SearchIcon } from '@patternfly/react-icons';
import { useAPI } from 'foremanReact/common/hooks/API/APIHooks';
import { foremanUrl } from 'foremanReact/common/helpers';
import { translate as __ } from 'foremanReact/common/I18n';
import SkeletonLoader from 'foremanReact/components/common/SkeletonLoader';
import { STATUS } from 'foremanReact/constants';
import CveTrendChart from './CveTrendChart';
import CveScansReports from './CveScansReports';
import CveFindingsModal from './CveFindingsModal';
import CveCompareModal from './CveCompareModal';
import { noReportsBody, noReportsTitle } from './cve_helpers';
import './cve_scans.scss';

const DEFAULT_PER_PAGE = 20;
const OVERVIEW_TAB = 0;
const REPORTS_TAB = 1;

const CveScansTab = ({ response }) => {
  const hostId = response?.id;
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(DEFAULT_PER_PAGE);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isCompareOpen, setIsCompareOpen] = useState(false);
  const [modalScanId, setModalScanId] = useState(null);
  const [modalFilter, setModalFilter] = useState('all');
  const [selectedScanIds, setSelectedScanIds] = useState([]);
  const [isTrendCompareMode, setIsTrendCompareMode] = useState(false);
  const [activeTabKey, setActiveTabKey] = useState(OVERVIEW_TAB);

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
    setIsTrendCompareMode(false);
  };
  const onPerPageSelect = (_event, newPerPage) => {
    setPerPage(newPerPage);
    setPage(1);
    setSelectedScanIds([]);
    setIsTrendCompareMode(false);
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
  const clearSelection = () => {
    setSelectedScanIds([]);
    setIsTrendCompareMode(false);
  };
  const toggleTrendCompareMode = () => {
    setIsTrendCompareMode(current => !current);
    setSelectedScanIds([]);
  };

  useEffect(() => {
    if (!isTrendCompareMode || selectedScanIds.length !== 2) return;
    setIsCompareOpen(true);
    setIsTrendCompareMode(false);
  }, [isTrendCompareMode, selectedScanIds]);

  if (!hostId) return null;

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
          <Tabs
            activeKey={activeTabKey}
            onSelect={(_event, tabIndex) => setActiveTabKey(tabIndex)}
            className="cve-scans-subtabs"
            ouiaId="cve-scans-subtabs"
          >
            <Tab
              eventKey={OVERVIEW_TAB}
              title={<TabTitleText>{__('Overview')}</TabTitleText>}
              ouiaId="cve-scans-overview-tab"
            >
              <section
                className="cve-scans-section"
                aria-label="CVE scan overview"
              >
                <CveTrendChart
                  scans={scans}
                  onOpen={scanId => openModal(scanId, 'all')}
                  compareMode={isTrendCompareMode}
                  selectedScanIds={selectedScanIds}
                  onToggleSelection={toggleScanSelection}
                  onToggleCompareMode={toggleTrendCompareMode}
                />
              </section>
            </Tab>
            <Tab
              eventKey={REPORTS_TAB}
              title={<TabTitleText>{__('Reports')}</TabTitleText>}
              ouiaId="cve-scans-reports-tab"
            >
              <CveScansReports
                scans={scans}
                itemCount={itemCount}
                page={page}
                perPage={perPage}
                onSetPage={onSetPage}
                onPerPageSelect={onPerPageSelect}
                selectedScanIds={selectedScanIds}
                selectedCount={selectedScans.length}
                onCompare={() => setIsCompareOpen(true)}
                onClearSelection={clearSelection}
                onToggleSelection={toggleScanSelection}
                onOpenModal={openModal}
                exportUrlFor={exportUrlFor}
              />
            </Tab>
          </Tabs>
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
