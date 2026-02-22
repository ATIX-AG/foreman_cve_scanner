/* eslint-disable import/no-unresolved */
import React, { useState } from 'react';
import PropTypes from 'prop-types';
import { Table, Tbody, Tr, Th, Thead, Td } from '@patternfly/react-table';
import {
  Text,
  TextContent,
  TextVariants,
  Button,
  DescriptionList,
  DescriptionListGroup,
  DescriptionListTerm,
  DescriptionListDescription,
  EmptyState,
  EmptyStateIcon,
  EmptyStateBody,
  Title,
} from '@patternfly/react-core';
import { SearchIcon } from '@patternfly/react-icons';
import { useAPI } from 'foremanReact/common/hooks/API/APIHooks';
import { foremanUrl } from 'foremanReact/common/helpers';
import { translate as __ } from 'foremanReact/common/I18n';
import CardTemplate from 'foremanReact/components/HostDetails/Templates/CardItem/CardTemplate';
import SkeletonLoader from 'foremanReact/components/common/SkeletonLoader';
import { STATUS } from 'foremanReact/constants';
import RelativeDateTime from 'foremanReact/components/common/dates/RelativeDateTime';
import SeverityIcon from './SeverityIcon';
import CveFindingsModal from './CveFindingsModal';
import CveHistoryTable from './CveHistoryTable';
import {
  noReportsBody,
  noReportsTitle,
  riskLevelFromWorst,
} from './cve_helpers';
import './cve_scans.scss';

const CveDetailsCard = ({ hostDetails }) => {
  const hostId = hostDetails?.id;
  const historyUrl = hostId
    ? foremanUrl(`/api/v2/hosts/${hostId}/cve_scans?per_page=3`)
    : null;
  const latestUrl = hostId
    ? foremanUrl(`/api/v2/hosts/${hostId}/cve_scans/latest`)
    : null;
  const { response: historyResponse, status } = useAPI('get', historyUrl, {
    key: `CVE_DETAILS_${hostId}`,
  });
  const { response: latestResponse, status: latestStatus } = useAPI(
    'get',
    latestUrl,
    { key: `CVE_DETAILS_LATEST_${hostId}` }
  );
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalScanId, setModalScanId] = useState(null);
  const [modalFilter, setModalFilter] = useState('all');
  if (!hostId) return null;
  const scans = historyResponse?.results || [];
  const latest = latestResponse?.id ? latestResponse : scans[0];
  const historyScans =
    latest && Array.isArray(scans)
      ? scans.filter(scan => scan.id !== latest.id)
      : scans;
  const findings = latest?.findings || [];
  const sortedFindings = [...findings].sort((a, b) => {
    const aTime = new Date(a.published || 0).getTime();
    const bTime = new Date(b.published || 0).getTime();
    return bTime - aTime;
  });
  const worst = latest?.summary?.worst || 'none';
  const riskLevel = riskLevelFromWorst(worst);
  const openModal = (scanId, filter) => {
    setModalScanId(scanId);
    setModalFilter(filter || 'all');
    setIsModalOpen(true);
  };
  return (
    <CardTemplate header={__('CVE scan details')} expandable masonryLayout>
      <SkeletonLoader status={status || latestStatus || STATUS.PENDING}>
        {!latest ? (
          <EmptyState>
            <EmptyStateIcon icon={SearchIcon} />
            <Title headingLevel="h4" size="md" ouiaId="cve-details-empty-title">
              {noReportsTitle()}
            </Title>
            <EmptyStateBody>{noReportsBody()}</EmptyStateBody>
          </EmptyState>
        ) : (
          <>
            <DescriptionList isCompact isHorizontal>
              <DescriptionListGroup>
                <DescriptionListTerm>{__('Report')}</DescriptionListTerm>
                <DescriptionListDescription>
                  <RelativeDateTime
                    date={latest.created_at}
                    defaultValue={__('Unknown time')}
                  />
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>{__('Total')}</DescriptionListTerm>
                <DescriptionListDescription>
                  <Button
                    variant="link"
                    className="cve-summary-link"
                    onClick={() => openModal(latest.id, 'all')}
                    ouiaId="cve-details-total-button"
                  >
                    <span
                      className={`cve-total-bubble cve-total-bubble--${riskLevel}`}
                    >
                      {latest.total}
                    </span>
                  </Button>{' '}
                  {__('CVEs by')} {latest.scanner}
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
            <div className="cve-counts cve-counts--compact">
              <Button
                variant="link"
                className="cve-summary-link"
                onClick={() => openModal(latest.id, 'critical')}
                ouiaId="cve-details-critical-button"
              >
                <span className="cve-count">
                  {__('critical')}
                  <span className="cve-bubble">{latest.critical}</span>
                </span>
              </Button>
              <Button
                variant="link"
                className="cve-summary-link"
                onClick={() => openModal(latest.id, 'medium')}
                ouiaId="cve-details-medium-button"
              >
                <span className="cve-count">
                  {__('medium')}
                  <span className="cve-bubble">{latest.medium}</span>
                </span>
              </Button>
              <Button
                variant="link"
                className="cve-summary-link"
                onClick={() => openModal(latest.id, 'high')}
                ouiaId="cve-details-high-button"
              >
                <span className="cve-count">
                  {__('high')}
                  <span className="cve-bubble">{latest.high}</span>
                </span>
              </Button>
              <Button
                variant="link"
                className="cve-summary-link"
                onClick={() => openModal(latest.id, 'low')}
                ouiaId="cve-details-low-button"
              >
                <span className="cve-count">
                  {__('low')}
                  <span className="cve-bubble">{latest.low}</span>
                </span>
              </Button>
            </div>

            {sortedFindings.length === 0 ? (
              <Text component={TextVariants.small} ouiaId="cve-details-empty">
                {__('No vulnerabilities reported')}
              </Text>
            ) : (
              <>
                <TextContent className="cve-section-title">
                  <Text
                    component={TextVariants.h5}
                    ouiaId="cve-details-cves-title"
                  >
                    {__('CVEs')}
                  </Text>
                </TextContent>
                <Table
                  variant="compact"
                  aria-label="CVE findings table"
                  ouiaId="cve-details-findings-table"
                >
                  <Thead>
                    <Tr ouiaId="cve-details-findings-header">
                      <Th>{__('Severity')}</Th>
                      <Th>{__('Package')}</Th>
                      <Th>{__('Installed')}</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {sortedFindings.slice(0, 5).map((finding, index) => (
                      <Tr
                        key={finding.id}
                        ouiaId={`cve-details-finding-row-${index}`}
                      >
                        <Td dataLabel={__('Severity')}>
                          <span className="cve-summary">
                            <SeverityIcon
                              severity={finding.severity?.toLowerCase()}
                            />
                            <span>{finding.severity}</span>
                          </span>
                        </Td>
                        <Td dataLabel={__('Package')}>{finding.name}</Td>
                        <Td dataLabel={__('Installed')}>{finding.version}</Td>
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
                {sortedFindings.length > 5 && (
                  <div className="cve-more">
                    <Button
                      variant="link"
                      className="cve-summary-link"
                      onClick={() => openModal(latest.id, 'all')}
                      ouiaId="cve-details-more-button"
                    >
                      {__('More')}
                    </Button>
                  </div>
                )}
              </>
            )}

            {historyScans.length > 0 && (
              <>
                <TextContent className="cve-section-title">
                  <Text
                    component={TextVariants.h4}
                    ouiaId="cve-details-recent-title"
                  >
                    {__('Recent scans')}
                  </Text>
                </TextContent>
                <CveHistoryTable scans={historyScans} onOpen={openModal} />
              </>
            )}
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
    </CardTemplate>
  );
};
CveDetailsCard.propTypes = {
  hostDetails: PropTypes.shape({ id: PropTypes.number }),
};
CveDetailsCard.defaultProps = {
  hostDetails: undefined,
};
export default CveDetailsCard;
