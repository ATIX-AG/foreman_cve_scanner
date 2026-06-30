/* eslint-disable import/no-unresolved */
import React from 'react';
import PropTypes from 'prop-types';
import {
  katelloFixDetailsUrl,
  katelloFixInstallUrl,
  katelloFixLabel,
  katelloFixTitle,
} from './cve_helpers';

const katelloFixClassName = fix =>
  `cve-katello-fix cve-katello-fix--${(
    fix?.status || 'unknown'
  ).toLowerCase()}`;

const CveKatelloFixLink = ({ fix, hostName }) => {
  const label = katelloFixLabel(fix);
  const title = katelloFixTitle(fix);
  const installUrl = katelloFixInstallUrl({ hostName, fix });
  const detailsUrl = katelloFixDetailsUrl(fix);
  const className = katelloFixClassName(fix);

  if (installUrl) {
    return (
      <a className={className} href={installUrl} title={title}>
        {label}
      </a>
    );
  }

  if ((fix?.status || '').toLowerCase() === 'applicable' && detailsUrl) {
    return (
      <a className={className} href={detailsUrl} title={title}>
        {label}
      </a>
    );
  }

  return (
    <span className={className} title={title}>
      {label}
    </span>
  );
};

CveKatelloFixLink.propTypes = {
  fix: PropTypes.shape({
    status: PropTypes.string,
    errata: PropTypes.arrayOf(PropTypes.object),
  }),
  hostName: PropTypes.string,
};

CveKatelloFixLink.defaultProps = {
  fix: undefined,
  hostName: undefined,
};

export default CveKatelloFixLink;
