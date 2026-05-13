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

  it('renders rows for scans', () => {
    const scansResponse = {
      results: [
        {
          id: 1,
          created_at: '2026-02-20',
          scanner: 'trivy',
          total: 10,
          critical: 1,
          high: 2,
          medium: 3,
          low: 4,
        },
        {
          id: 2,
          created_at: '2026-02-21',
          scanner: 'grype',
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

    expect(wrapper.text()).toContain('Reported at');
    expect(wrapper.text()).toContain('trivy');
    expect(wrapper.text()).toContain('grype');
    expect(wrapper.text()).toContain('Trend');
    expect(wrapper.text()).toContain('Export CSV');
    expect(wrapper.text()).toContain('Compare selected');
  });

  it('opens compare modal when two scans are selected', () => {
    const scansResponse = {
      results: [
        {
          id: 1,
          created_at: '2026-02-20',
          scanner: 'trivy',
          total: 10,
          critical: 1,
          high: 2,
          medium: 3,
          low: 4,
        },
        {
          id: 2,
          created_at: '2026-02-21',
          scanner: 'grype',
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

  it('does not render when host id is missing', () => {
    useAPI.mockReturnValue({ response: { results: [] }, status: 'RESOLVED' });

    const wrapper = mount(<CveScansTab response={{}} />);
    expect(wrapper.isEmptyRender()).toBe(true);
  });
});
