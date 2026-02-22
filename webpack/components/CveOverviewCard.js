/* eslint-disable import/no-unresolved */
import React from 'react';
import PropTypes from 'prop-types';
import { Text, TextContent, TextVariants } from '@patternfly/react-core';
import { useAPI } from 'foremanReact/common/hooks/API/APIHooks';
import { foremanUrl } from 'foremanReact/common/helpers';
import { translate as __ } from 'foremanReact/common/I18n';
import CardTemplate from 'foremanReact/components/HostDetails/Templates/CardItem/CardTemplate';
import SkeletonLoader from 'foremanReact/components/common/SkeletonLoader';
import { STATUS } from 'foremanReact/constants';
import SeverityIcon from './SeverityIcon';
import { noReportsTitle } from './cve_helpers';
import './cve_scans.scss';

const CveOverviewCard = ({ hostDetails }) => {
  const hostId = hostDetails?.id;
  const url = hostId
    ? foremanUrl(`/api/v2/hosts/${hostId}/cve_scans/latest`)
    : null;
  const { response, status } = useAPI('get', url, {
    key: `CVE_OVERVIEW_${hostId}`,
  });

  if (!hostId) return null;

  const total = response?.total || 0;
  const worst = response?.summary?.worst || 'none';

  return (
    <CardTemplate header={__('CVE findings')}>
      <SkeletonLoader status={status || STATUS.PENDING}>
        {!response ? (
          <TextContent ouiaId="cve-overview-empty">
            <Text
              component={TextVariants.small}
              ouiaId="cve-overview-empty-text"
            >
              {noReportsTitle()}
            </Text>
          </TextContent>
        ) : (
          <div className="cve-overview">
            <div className="cve-summary">
              <SeverityIcon severity={worst} />
              <Text component={TextVariants.h2} ouiaId="cve-overview-total">
                {total}
              </Text>
            </div>
            <Text component={TextVariants.small} ouiaId="cve-overview-caption">
              {__('Total findings in latest scan')}
            </Text>
          </div>
        )}
      </SkeletonLoader>
    </CardTemplate>
  );
};

CveOverviewCard.propTypes = {
  hostDetails: PropTypes.shape({ id: PropTypes.number }),
};

CveOverviewCard.defaultProps = {
  hostDetails: undefined,
};

export default CveOverviewCard;
