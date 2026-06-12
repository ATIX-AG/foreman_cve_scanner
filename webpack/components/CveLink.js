/* eslint-disable import/no-unresolved */
import React from 'react';
import PropTypes from 'prop-types';

const SAFE_URL = /^https?:\/\//i;

const CveLink = ({ id, url }) => {
  if (url && SAFE_URL.test(url)) {
    return (
      <a href={url} target="_blank" rel="noreferrer">
        {id}
      </a>
    );
  }

  return <>{id}</>;
};

CveLink.propTypes = {
  id: PropTypes.string.isRequired,
  url: PropTypes.string,
};

CveLink.defaultProps = {
  url: undefined,
};

export default CveLink;
