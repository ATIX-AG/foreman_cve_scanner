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
  beforeEach(() => {
    useAPI.mockReset();
  });

  it('renders overview and reports sub-tabs', () => {
    const scansResponse = {
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

    useAPI.mockReturnValue({ response: scansResponse, status: 'RESOLVED' });

    const wrapper = mount(<CveScansTab response={{ id: 1 }} />);

    expect(wrapper.text()).toContain('Overview');
    expect(wrapper.text()).toContain('Reports');
    expect(wrapper.text()).toContain('Trend');
    expect(wrapper.text()).toContain('Latest total');
  });

  it('opens compare modal from overview trend selection', () => {
    const scansResponse = {
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

    useAPI.mockReturnValue({ response: scansResponse, status: 'RESOLVED' });

    const wrapper = mount(<CveScansTab response={{ id: 1 }} />);

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

  it('renders scan rows in the reports sub-tab', () => {
    const scansResponse = {
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

    useAPI.mockReturnValue({ response: scansResponse, status: 'RESOLVED' });

    const wrapper = mount(<CveScansTab response={{ id: 1 }} />);

    wrapper
      .find('[role="tab"]')
      .filterWhere(node => node.text() === 'Reports')
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
    const scansResponse = {
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

    useAPI.mockReturnValue({ response: scansResponse, status: 'RESOLVED' });

    const wrapper = mount(<CveScansTab response={{ id: 1 }} />);

    wrapper
      .find('[role="tab"]')
      .filterWhere(node => node.text() === 'Reports')
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
    useAPI.mockReturnValue({ response: { results: [] }, status: 'RESOLVED' });

    const wrapper = mount(<CveScansTab response={{ id: 1 }} />);
    expect(wrapper.text()).toContain('No CVE reports for this host');
  });

  it('renders trend overview when recent scans have no cves', () => {
    const scansResponse = {
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
    };

    useAPI.mockReturnValue({ response: scansResponse, status: 'RESOLVED' });

    const wrapper = mount(<CveScansTab response={{ id: 1 }} />);
    expect(wrapper.text()).toContain('Trend');
    expect(wrapper.text()).toContain('Latest total');
    expect(wrapper.text()).toContain('0');
  });

  it('does not render when host id is missing', () => {
    useAPI.mockReturnValue({ response: { results: [] }, status: 'RESOLVED' });

    const wrapper = mount(<CveScansTab response={{}} />);
    expect(wrapper.isEmptyRender()).toBe(true);
  });
});
