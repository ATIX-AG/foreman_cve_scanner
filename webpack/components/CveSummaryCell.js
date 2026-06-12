/* eslint-disable import/no-unresolved */
import React, { useEffect, useState } from 'react';
import PropTypes from 'prop-types';
import { Spinner } from '@patternfly/react-core';
import { translate as __ } from 'foremanReact/common/I18n';
import SeverityIcon from './SeverityIcon';
import CveFindingsModal from './CveFindingsModal';
import {
  getCachedCveSummary,
  subscribeToCveSummary,
} from './cve_summary_store';
import './cve_scans.scss';

const CveSummaryCell = ({ hostId, hostName }) => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [response, setResponse] = useState(
    hostId ? getCachedCveSummary(hostId) : null
  );
  const [isLoaded, setIsLoaded] = useState(
    hostId ? getCachedCveSummary(hostId) !== undefined : true
  );

  useEffect(() => {
    if (!hostId) {
      setResponse(null);
      setIsLoaded(true);
      return undefined;
    }

    const cached = getCachedCveSummary(hostId);
    setResponse(cached);
    setIsLoaded(cached !== undefined);

    return subscribeToCveSummary(hostId, value => {
      setResponse(value);
      setIsLoaded(true);
    });
  }, [hostId]);

  if (!hostId) return <span className="cve-summary-empty">--</span>;
  if (!isLoaded) {
    return <Spinner size="sm" aria-label={__('Loading CVE findings')} />;
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
