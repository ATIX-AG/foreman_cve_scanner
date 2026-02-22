/* eslint-disable import/no-unresolved */
import React, { useState } from 'react';
import PropTypes from 'prop-types';
import { Spinner } from '@patternfly/react-core';
import { useAPI } from 'foremanReact/common/hooks/API/APIHooks';
import { foremanUrl } from 'foremanReact/common/helpers';
import { translate as __ } from 'foremanReact/common/I18n';
import { STATUS } from 'foremanReact/constants';
import SeverityIcon from './SeverityIcon';
import CveFindingsModal from './CveFindingsModal';
import './cve_scans.scss';

const CveSummaryCell = ({ hostId, hostName }) => {
  const url = hostId
    ? foremanUrl(`/api/v2/hosts/${hostId}/cve_scans/latest`)
    : null;
  const { response, status } = useAPI('get', url, {
    key: `CVE_SUMMARY_${hostId}`,
  });

  const [isModalOpen, setIsModalOpen] = useState(false);
  if (!hostId) return <span className="cve-summary-empty">--</span>;
  if (status === STATUS.PENDING) {
    return (
      <Spinner
        size="sm"
        aria-label={__('Loading CVE findings')}
        ouiaId="cve-summary-loading"
      />
    );
  }

  if (!response) return <span className="cve-summary-empty">--</span>;

  const total = response.total || 0;
  const worst = response.summary?.worst || 'none';
  const scanId = response.id;
  const title = `${hostName || __('Host')}: ${total} ${__('findings')}`;

  return (
    <>
      <button
        type="button"
        className="cve-summary cve-summary-link"
        title={title}
        onClick={() => setIsModalOpen(true)}
      >
        <SeverityIcon severity={worst} />
        <span className="cve-summary-count">{total}</span>
      </button>
      <CveFindingsModal
        isOpen={isModalOpen && !!scanId}
        onClose={() => setIsModalOpen(false)}
        hostId={hostId}
        scanId={scanId}
        initialFilter="all"
      />
    </>
  );
};

CveSummaryCell.propTypes = {
  hostId: PropTypes.number,
  hostName: PropTypes.string,
};

CveSummaryCell.defaultProps = {
  hostId: undefined,
  hostName: undefined,
};

export default CveSummaryCell;
