/* eslint-disable import/no-unresolved */
import React from 'react';
import PropTypes from 'prop-types';
import { Modal, Button } from '@patternfly/react-core';
import { useAPI } from 'foremanReact/common/hooks/API/APIHooks';
import { foremanUrl } from 'foremanReact/common/helpers';
import { translate as __ } from 'foremanReact/common/I18n';
import CveFindingsView from './CveFindingsView';
import './cve_scans.scss';

const CveFindingsModal = ({
  isOpen,
  onClose,
  hostId,
  hostName,
  scanId,
  initialFilter,
}) => {
  const normalizedScanId =
    scanId !== null && scanId !== undefined && String(scanId).trim() !== ''
      ? scanId
      : null;
  const url = normalizedScanId
    ? foremanUrl(`/api/v2/hosts/${hostId}/cve_scans/${normalizedScanId}`)
    : foremanUrl(`/api/v2/hosts/${hostId}/cve_scans/latest`);

  const { response, status } = useAPI(isOpen ? 'get' : null, url, {
    key: `CVE_SCAN_${hostId}_${normalizedScanId || 'latest'}`,
  });

  return (
    <Modal
      title={__('CVE findings')}
      isOpen={isOpen}
      onClose={onClose}
      width="70%"
      maxWidth="70%"
      ouiaId="cve-findings-modal"
      actions={[
        <Button
          key="close"
          variant="primary"
          onClick={onClose}
          ouiaId="cve-findings-close"
        >
          {__('Close')}
        </Button>,
      ]}
    >
      <CveFindingsView
        scan={response}
        status={status}
        initialFilter={initialFilter}
        hostName={hostName}
      />
    </Modal>
  );
};

CveFindingsModal.propTypes = {
  isOpen: PropTypes.bool.isRequired,
  onClose: PropTypes.func.isRequired,
  hostId: PropTypes.number.isRequired,
  hostName: PropTypes.string,
  scanId: PropTypes.number,
  initialFilter: PropTypes.string,
};

CveFindingsModal.defaultProps = {
  hostName: undefined,
  scanId: undefined,
  initialFilter: 'all',
};

export default CveFindingsModal;
