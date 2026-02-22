/* eslint-disable import/no-unresolved */
import React from 'react';
import PropTypes from 'prop-types';
import {
  ExclamationCircleIcon,
  ExclamationTriangleIcon,
  InfoCircleIcon,
  CheckCircleIcon,
} from '@patternfly/react-icons';
import { Icon } from '@patternfly/react-core';
import './cve_scans.scss';

const SeverityIcon = ({ severity }) => {
  switch (severity) {
    case 'critical':
      return (
        <Icon className="cve-severity cve-severity--critical">
          <ExclamationCircleIcon />
        </Icon>
      );
    case 'high':
      return (
        <Icon className="cve-severity cve-severity--high">
          <ExclamationTriangleIcon />
        </Icon>
      );
    case 'medium':
      return (
        <Icon className="cve-severity cve-severity--medium">
          <InfoCircleIcon />
        </Icon>
      );
    case 'low':
      return (
        <Icon className="cve-severity cve-severity--low">
          <InfoCircleIcon />
        </Icon>
      );
    default:
      return (
        <Icon className="cve-severity cve-severity--none">
          <CheckCircleIcon />
        </Icon>
      );
  }
};

SeverityIcon.propTypes = {
  severity: PropTypes.string,
};

SeverityIcon.defaultProps = {
  severity: 'none',
};

export default SeverityIcon;
