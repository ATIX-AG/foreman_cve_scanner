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
import CveFindingsView from './CveFindingsView';
import CveScansReports from './CveScansReports';
import CveFindingsModal from './CveFindingsModal';
import CveCompareModal from './CveCompareModal';
import useModalScan from './useModalScan';
import { noReportsBody, noReportsTitle } from './cve_helpers';
import './cve_scans.scss';

const DEFAULT_PER_PAGE = 20;
const LATEST_SCAN_TAB = 0;
const TRENDS_TAB = 1;
const HISTORY_TAB = 2;

const CveScansTab = ({ response }) => {
  const hostId = response?.id;
  const hostName = response?.name;
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(DEFAULT_PER_PAGE);
  const [isCompareOpen, setIsCompareOpen] = useState(false);
  const [selectedScanIds, setSelectedScanIds] = useState([]);
  const [isTrendCompareMode, setIsTrendCompareMode] = useState(false);
  const [activeTabKey, setActiveTabKey] = useState(LATEST_SCAN_TAB);
  const { isOpen, scanId, filter, openModal, closeModal } = useModalScan();

  const historyUrl = hostId
    ? foremanUrl(
        `/api/v2/hosts/${hostId}/cve_scans?page=${page}&per_page=${perPage}`
      )
    : null;
  const latestUrl = hostId
    ? foremanUrl(`/api/v2/hosts/${hostId}/cve_scans/latest`)
    : null;
  const { response: apiResponse, status } = useAPI('get', historyUrl, {
    key: `CVE_SCANS_TAB_${hostId}_${page}_${perPage}`,
  });
  const { response: latestResponse, status: latestStatus } = useAPI(
    'get',
    latestUrl,
    {
      key: `CVE_SCANS_TAB_LATEST_${hostId}`,
    }
  );

  const scans = useMemo(() => apiResponse?.results || [], [apiResponse]);
  const latestScan = latestResponse?.id ? latestResponse : null;
  const selectedScans = useMemo(
    () => scans.filter(scan => selectedScanIds.includes(scan.id)),
    [scans, selectedScanIds]
  );
  const orderedCompareIds = useMemo(
    () =>
      [...selectedScans]
        .sort(
          (a, b) =>
            new Date(a.scanned_at || 0).getTime() -
            new Date(b.scanned_at || 0).getTime()
        )
        .map(scan => scan.id),
    [selectedScans]
  );
  const itemCount = apiResponse?.total ?? scans.length;
  const exportUrlFor = reportId =>
    foremanUrl(`/api/v2/hosts/${hostId}/cve_scans/${reportId}/export`);

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
  const toggleScanSelection = reportId => {
    setSelectedScanIds(currentSelection => {
      if (currentSelection.includes(reportId)) {
        return currentSelection.filter(id => id !== reportId);
      }
      if (currentSelection.length >= 2) return currentSelection;
      return [...currentSelection, reportId];
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
              eventKey={LATEST_SCAN_TAB}
              title={<TabTitleText>{__('Latest Scan')}</TabTitleText>}
              ouiaId="cve-scans-latest-tab"
            >
              <section
                className="cve-scans-section"
                aria-label="Latest CVE scan"
              >
                <CveFindingsView
                  scan={latestScan}
                  status={latestStatus}
                  initialFilter="all"
                  hostName={hostName}
                />
              </section>
            </Tab>
            <Tab
              eventKey={TRENDS_TAB}
              title={<TabTitleText>{__('Trends')}</TabTitleText>}
              ouiaId="cve-scans-trends-tab"
            >
              <section
                className="cve-scans-section"
                aria-label="CVE scan overview"
              >
                <CveTrendChart
                  scans={scans}
                  onOpen={reportId => openModal(reportId, 'all')}
                  compareMode={isTrendCompareMode}
                  selectedScanIds={selectedScanIds}
                  onToggleSelection={toggleScanSelection}
                  onToggleCompareMode={toggleTrendCompareMode}
                />
              </section>
            </Tab>
            <Tab
              eventKey={HISTORY_TAB}
              title={<TabTitleText>{__('History')}</TabTitleText>}
              ouiaId="cve-scans-history-tab"
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
        isOpen={isOpen}
        onClose={closeModal}
        hostId={hostId}
        hostName={hostName}
        scanId={scanId}
        initialFilter={filter}
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
    name: PropTypes.string,
  }),
};

CveScansTab.defaultProps = {
  response: undefined,
};

export default CveScansTab;
