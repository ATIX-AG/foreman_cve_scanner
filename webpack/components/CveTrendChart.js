/* eslint-disable import/no-unresolved */
import React, { useMemo } from 'react';
import PropTypes from 'prop-types';
import {
  Text,
  TextContent,
  TextVariants,
  Tooltip,
} from '@patternfly/react-core';
import { translate as __ } from 'foremanReact/common/I18n';
import { formatDateTime } from './cve_helpers';

const TREND_LIMIT = 10;
const STACK_ORDER = ['low', 'medium', 'high', 'critical'];
const TREND_LEGEND = [
  { key: 'critical', label: __('Critical') },
  { key: 'high', label: __('High') },
  { key: 'medium', label: __('Medium') },
  { key: 'low', label: __('Low') },
];
const totalDeltaText = __(
  'Difference in total CVE count compared to the previous scan.'
);
const criticalHighDeltaText = __(
  'Difference in critical and high CVE count compared to the previous scan.'
);

const shortDateLabel = value => {
  const date = new Date(value || 0);
  if (Number.isNaN(date.getTime())) return '--';
  return new Intl.DateTimeFormat(undefined, {
    day: '2-digit',
    month: 'short',
  })
    .format(date)
    .replace(',', '');
};

const formatDelta = value => {
  if (value > 0) return `+${value}`;
  if (value < 0) return String(value);
  return '0';
};

const deltaClassName = value => {
  if (value > 0) return 'is-up';
  if (value < 0) return 'is-down';
  return 'is-flat';
};

const CveTrendChart = ({ scans, onOpen }) => {
  const visibleScans = useMemo(
    () => [...scans].slice(0, TREND_LIMIT).reverse(),
    [scans]
  );
  const latestScan = scans[0];
  const previousScan = scans[1];
  const maxTotal = Math.max(...visibleScans.map(scan => scan.total || 0), 1);
  const criticalHighDelta =
    (latestScan?.critical || 0) +
    (latestScan?.high || 0) -
    ((previousScan?.critical || 0) + (previousScan?.high || 0));
  const totalDelta = (latestScan?.total || 0) - (previousScan?.total || 0);

  if (!latestScan) return null;

  return (
    <section className="cve-trend" aria-label="CVE trend chart">
      <TextContent className="cve-section-title">
        <Text component={TextVariants.h4} ouiaId="cve-trend-title">
          {__('Trend')}
        </Text>
        <Text component={TextVariants.small} ouiaId="cve-trend-subtitle">
          {__('Last %s scans').replace('%s', visibleScans.length)}
        </Text>
      </TextContent>

      <div className="cve-trend-summary">
        <div className="cve-trend-card">
          <span className="cve-trend-card-label">{__('Latest total')}</span>
          <span className="cve-trend-card-value">{latestScan.total}</span>
        </div>
        <div className="cve-trend-card">
          <Tooltip content={criticalHighDeltaText}>
            <span className="cve-trend-card-label cve-trend-card-label--help">
              {__('Critical/high delta')}
            </span>
          </Tooltip>
          <span
            className={`cve-trend-card-value ${deltaClassName(
              criticalHighDelta
            )}`}
          >
            {previousScan
              ? formatDelta(criticalHighDelta)
              : __('No previous scan')}
          </span>
        </div>
        <div className="cve-trend-card">
          <Tooltip content={totalDeltaText}>
            <span className="cve-trend-card-label cve-trend-card-label--help">
              {__('Total delta')}
            </span>
          </Tooltip>
          <span
            className={`cve-trend-card-value ${deltaClassName(totalDelta)}`}
          >
            {previousScan ? formatDelta(totalDelta) : __('No previous scan')}
          </span>
        </div>
        <div className="cve-trend-card">
          <span className="cve-trend-card-label">{__('Last scanned')}</span>
          <span className="cve-trend-card-value cve-trend-card-value--small">
            {formatDateTime(latestScan.created_at)}
          </span>
        </div>
      </div>

      <div className="cve-trend-legend" aria-label="CVE trend legend">
        {TREND_LEGEND.map(item => (
          <span key={item.key} className="cve-trend-legend-item">
            <span
              className={`cve-trend-legend-swatch cve-trend-segment--${item.key}`}
            />
            <span>{item.label}</span>
          </span>
        ))}
      </div>

      <div className="cve-trend-bars">
        {visibleScans.map(scan => (
          <button
            key={scan.id}
            type="button"
            className="cve-trend-bar-button"
            onClick={() => onOpen(scan.id)}
            aria-label={__('Open scan details for %s').replace(
              '%s',
              formatDateTime(scan.created_at)
            )}
            title={`${formatDateTime(scan.created_at)} | ${__('Total')}: ${
              scan.total
            } | ${__('Critical')}: ${scan.critical} | ${__('High')}: ${
              scan.high
            } | ${__('Medium')}: ${scan.medium} | ${__('Low')}: ${scan.low}`}
          >
            <span className="cve-trend-bar-frame">
              {STACK_ORDER.map(level => (
                <span
                  key={level}
                  className={`cve-trend-segment cve-trend-segment--${level}`}
                  style={{
                    height: `${((scan[level] || 0) / maxTotal) * 100}%`,
                  }}
                />
              ))}
            </span>
            <span className="cve-trend-bar-total">{scan.total}</span>
            <span className="cve-trend-bar-label">
              {shortDateLabel(scan.created_at)}
            </span>
          </button>
        ))}
      </div>
    </section>
  );
};

CveTrendChart.propTypes = {
  scans: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.number.isRequired,
      created_at: PropTypes.string,
      total: PropTypes.number,
      critical: PropTypes.number,
      high: PropTypes.number,
      medium: PropTypes.number,
      low: PropTypes.number,
    })
  ),
  onOpen: PropTypes.func,
};

CveTrendChart.defaultProps = {
  scans: [],
  onOpen: () => {},
};

export default CveTrendChart;
