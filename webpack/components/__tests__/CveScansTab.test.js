/* eslint-disable import/no-unresolved */
import React from 'react';
import { mount } from 'enzyme';
import CveScansTab from '../CveScansTab';

jest.mock('foremanReact/common/hooks/API/APIHooks', () => ({
  useAPI: jest.fn(),
}));

jest.mock('foremanReact/components/common/SkeletonLoader', () => (
  { children }
) => <div>{children}</div>);

jest.mock('foremanReact/components/common/dates/RelativeDateTime', () => (
  { date, defaultValue }
) => <span>{date || defaultValue}</span>);

jest.mock('../CveFindingsModal', () => () => <div data-test="modal" />);
jest.mock('../CveCompareModal', () => ({ isOpen, scanIds }) =>
  isOpen ? <div data-test="compare-modal">{scanIds.join(',')}</div> : null
);

const { useAPI } = require('foremanReact/common/hooks/API/APIHooks');

describe('CveScansTab', () => {
  const historyResponse = {
    results: [
      {
        id: 1,
        scanned_at: '2026-02-20',
        scanner: 'trivy',
        source: 'rex',
        total: 10,
        critical: 1,
        high: 2,
        medium: 3,
        low: 4,
      },
      {
        id: 2,
        scanned_at: '2026-02-21',
        scanner: 'grype',
        source: 'external',
        total: 5,
        critical: 0,
        high: 1,
        medium: 1,
        low: 3,
      },
    ],
    total: 2,
  };
  const latestResponse = {
    id: 2,
    scanned_at: '2026-02-21',
    scanner: 'grype',
    source: 'external',
    total: 5,
    findings: [
      {
        id: 'CVE-2026-0001',
        name: 'openssl',
        version: '1.0',
        fixed: '1.1',
        status: 'open',
        severity: 'HIGH',
        title: 'OpenSSL issue',
        published: '2026-02-11T00:00:00Z',
        url: 'https://example.test/CVE-2026-0001',
      },
    ],
  };

  const mockScanApis = ({
    latest = latestResponse,
    history = historyResponse,
    latestStatus = 'RESOLVED',
    historyStatus = 'RESOLVED',
  } = {}) => {
    useAPI.mockImplementation((_method, url) => {
      if (url && url.includes('/cve_scans/latest')) {
        return { response: latest, status: latestStatus };
      }
      return { response: history, status: historyStatus };
    });
  };

  beforeEach(() => {
    useAPI.mockReset();
  });

  it('renders latest scan, trends and history tabs', () => {
    mockScanApis();

    const wrapper = mount(<CveScansTab response={{ id: 1 }} />);

    expect(wrapper.text()).toContain('Latest Scan');
    expect(wrapper.text()).toContain('Trends');
    expect(wrapper.text()).toContain('History');
    expect(wrapper.text()).toContain('Report from');
    expect(wrapper.text()).toContain('grype / external');
    expect(wrapper.text()).toContain('openssl');
  });

  it('renders a success state when the latest scan has no findings', () => {
    mockScanApis({
      latest: {
        id: 2,
        scanned_at: '2026-02-21',
        scanner: 'grype',
        source: 'external',
        total: 0,
        findings: [],
      },
    });

    const wrapper = mount(<CveScansTab response={{ id: 1 }} />);

    expect(wrapper.text()).toContain('No CVEs found');
    expect(wrapper.text()).toContain(
      'The latest CVE scan found no vulnerabilities for this host.'
    );
  });

  it('opens compare modal from trends selection', () => {
    mockScanApis();

    const wrapper = mount(<CveScansTab response={{ id: 1 }} />);

    wrapper
      .find('[role="tab"]')
      .filterWhere(node => node.text() === 'Trends')
      .first()
      .simulate('click');
    wrapper.update();

    wrapper
      .find('button')
      .filterWhere(node => node.text() === 'Compare 2 reports')
      .first()
      .simulate('click');
    wrapper.update();

    wrapper.find('button.cve-trend-bar-button').at(0).simulate('click');
    wrapper.find('button.cve-trend-bar-button').at(1).simulate('click');
    wrapper.update();

    expect(wrapper.find('[data-test="compare-modal"]').text()).toBe('1,2');
  });

  it('renders scan rows in the history tab', () => {
    mockScanApis();

    const wrapper = mount(<CveScansTab response={{ id: 1 }} />);

    wrapper
      .find('[role="tab"]')
      .filterWhere(node => node.text() === 'History')
      .first()
      .simulate('click');
    wrapper.update();

    expect(wrapper.text()).toContain('Scanned at');
    expect(wrapper.text()).toContain('trivy');
    expect(wrapper.text()).toContain('grype / external');
    expect(wrapper.text()).toContain('Export CSV');
    expect(wrapper.text()).toContain('Compare selected');
  });

  it('opens compare modal when two scans are selected', () => {
    mockScanApis();

    const wrapper = mount(<CveScansTab response={{ id: 1 }} />);

    wrapper
      .find('[role="tab"]')
      .filterWhere(node => node.text() === 'History')
      .first()
      .simulate('click');
    wrapper.update();

    wrapper.find('input#cve-scan-select-1').simulate('change');
    wrapper.find('input#cve-scan-select-2').simulate('change');
    wrapper.update();

    wrapper
      .find('button')
      .filterWhere(node => node.text() === 'Compare selected')
      .first()
      .simulate('click');
    wrapper.update();

    expect(wrapper.find('[data-test="compare-modal"]').text()).toBe('1,2');
  });

  it('renders empty state with no scans', () => {
    mockScanApis({ latest: null, history: { results: [] } });

    const wrapper = mount(<CveScansTab response={{ id: 1 }} />);
    expect(wrapper.text()).toContain('No CVE reports for this host');
  });

  it('renders trend content in the trends tab when recent scans have no cves', () => {
    mockScanApis({
      latest: {
        id: 1,
        scanned_at: '2026-02-20',
        scanner: 'trivy',
        source: 'rex',
        total: 0,
        findings: [],
      },
      history: {
        results: [
          {
            id: 1,
            scanned_at: '2026-02-20',
            scanner: 'trivy',
            source: 'rex',
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
          },
        ],
        total: 1,
      },
    });

    const wrapper = mount(<CveScansTab response={{ id: 1 }} />);

    wrapper
      .find('[role="tab"]')
      .filterWhere(node => node.text() === 'Trends')
      .first()
      .simulate('click');
    wrapper.update();

    expect(wrapper.text()).toContain('Latest total');
    expect(wrapper.text()).toContain('0');
  });

  it('does not render when host id is missing', () => {
    mockScanApis({ latest: null, history: { results: [] } });

    const wrapper = mount(<CveScansTab response={{}} />);
    expect(wrapper.isEmptyRender()).toBe(true);
  });
});
