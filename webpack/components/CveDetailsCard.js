/* eslint-disable import/no-unresolved */
import React from 'react';
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
import { CheckCircleIcon, SearchIcon } from '@patternfly/react-icons';
import { useAPI } from 'foremanReact/common/hooks/API/APIHooks';
import { foremanUrl } from 'foremanReact/common/helpers';
import { translate as __ } from 'foremanReact/common/I18n';
import CardTemplate from 'foremanReact/components/HostDetails/Templates/CardItem/CardTemplate';
import SkeletonLoader from 'foremanReact/components/common/SkeletonLoader';
import { STATUS } from 'foremanReact/constants';
import RelativeDateTime from 'foremanReact/components/common/dates/RelativeDateTime';
import SeverityIcon from './SeverityIcon';
import CveFindingsModal from './CveFindingsModal';
import useModalScan from './useModalScan';
import {
  noFindingsBody,
  noFindingsTitle,
  formatScanOrigin,
  noReportsBody,
  noReportsTitle,
  riskLevelFromWorst,
  severityRank,
} from './cve_helpers';
import './cve_scans.scss';

const CveDetailsCard = ({ hostDetails }) => {
  const hostId = hostDetails?.id;
  const latestUrl = hostId
    ? foremanUrl(`/api/v2/hosts/${hostId}/cve_scans/latest`)
    : null;
  const { response: latestResponse, status: latestStatus } = useAPI(
    'get',
    latestUrl,
    { key: `CVE_DETAILS_LATEST_${hostId}` }
  );
  const { isOpen, scanId, filter, openModal, closeModal } = useModalScan();
  if (!hostId) return null;
  const latest = latestResponse?.id ? latestResponse : null;
  const findings = latest?.findings || [];
  const sortedFindings = [...findings].sort((a, b) => {
    const severityDiff = severityRank(b.severity) - severityRank(a.severity);
    if (severityDiff !== 0) return severityDiff;
    const aTime = new Date(a.published || 0).getTime();
    const bTime = new Date(b.published || 0).getTime();
    return bTime - aTime;
  });
  // The host details preview should show ranked CVEs first and only fall back
  // to unknown severities when a scan has no ranked findings at all.
  const previewFindings = sortedFindings.filter(
    finding => severityRank(finding.severity) > 0
  );
  const visibleFindings =
    previewFindings.length > 0
      ? previewFindings.slice(0, 5)
      : sortedFindings.slice(0, 5);
  const worst = latest?.summary?.worst || 'none';
  const riskLevel = riskLevelFromWorst(worst);
  const origin = formatScanOrigin(latest?.scanner, latest?.source);
  return (
    <CardTemplate header={__('CVE scan details')} expandable masonryLayout>
      <SkeletonLoader status={latestStatus || STATUS.PENDING}>
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
            <div className="cve-overview">
              <DescriptionList
                isCompact
                isHorizontal
                className="cve-overview-meta"
              >
                <DescriptionListGroup>
                  <DescriptionListTerm>{__('Report')}</DescriptionListTerm>
                  <DescriptionListDescription>
                    <RelativeDateTime
                      date={latest.scanned_at}
                      defaultValue={__('Unknown time')}
                    />
                  </DescriptionListDescription>
                </DescriptionListGroup>
                <DescriptionListGroup>
                  <DescriptionListTerm>{__('Total')}</DescriptionListTerm>
                  <DescriptionListDescription>
                    <span className="cve-overview-total">
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
                      </Button>
                      <span className="cve-overview-source">{origin}</span>
                    </span>
                  </DescriptionListDescription>
                </DescriptionListGroup>
              </DescriptionList>
              <div className="cve-counts cve-counts--compact">
                <Button
                  variant="plain"
                  className="cve-count-card cve-count-card--critical"
                  onClick={() => openModal(latest.id, 'critical')}
                  ouiaId="cve-details-critical-button"
                >
                  <span className="cve-count">
                    <span className="cve-count-label">
                      <SeverityIcon severity="critical" />
                      <span>{__('critical')}</span>
                    </span>
                    <span className="cve-bubble cve-bubble--critical">
                      {latest.critical}
                    </span>
                  </span>
                </Button>
                <Button
                  variant="plain"
                  className="cve-count-card cve-count-card--medium"
                  onClick={() => openModal(latest.id, 'medium')}
                  ouiaId="cve-details-medium-button"
                >
                  <span className="cve-count">
                    <span className="cve-count-label">
                      <SeverityIcon severity="medium" />
                      <span>{__('medium')}</span>
                    </span>
                    <span className="cve-bubble cve-bubble--medium">
                      {latest.medium}
                    </span>
                  </span>
                </Button>
                <Button
                  variant="plain"
                  className="cve-count-card cve-count-card--high"
                  onClick={() => openModal(latest.id, 'high')}
                  ouiaId="cve-details-high-button"
                >
                  <span className="cve-count">
                    <span className="cve-count-label">
                      <SeverityIcon severity="high" />
                      <span>{__('high')}</span>
                    </span>
                    <span className="cve-bubble cve-bubble--high">
                      {latest.high}
                    </span>
                  </span>
                </Button>
                <Button
                  variant="plain"
                  className="cve-count-card cve-count-card--low"
                  onClick={() => openModal(latest.id, 'low')}
                  ouiaId="cve-details-low-button"
                >
                  <span className="cve-count">
                    <span className="cve-count-label">
                      <SeverityIcon severity="low" />
                      <span>{__('low')}</span>
                    </span>
                    <span className="cve-bubble cve-bubble--low">
                      {latest.low}
                    </span>
                  </span>
                </Button>
              </div>
            </div>

            {visibleFindings.length === 0 ? (
              <EmptyState className="cve-empty-state cve-empty-state--success">
                <EmptyStateIcon icon={CheckCircleIcon} />
                <Title
                  headingLevel="h4"
                  size="md"
                  ouiaId="cve-details-clean-title"
                >
                  {noFindingsTitle()}
                </Title>
                <EmptyStateBody>{noFindingsBody()}</EmptyStateBody>
              </EmptyState>
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
                    {visibleFindings.map((finding, index) => (
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
                {sortedFindings.length > visibleFindings.length && (
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
          </>
        )}
      </SkeletonLoader>
      <CveFindingsModal
        isOpen={isOpen}
        onClose={closeModal}
        hostId={hostId}
        scanId={scanId}
        initialFilter={filter}
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
