/* eslint-disable import/no-unresolved */
import React from 'react';
import { mount } from 'enzyme';
import CveDetailsCard from '../CveDetailsCard';

jest.mock('foremanReact/common/hooks/API/APIHooks', () => ({
  useAPI: jest.fn(),
}));

jest.mock('foremanReact/components/HostDetails/Templates/CardItem/CardTemplate', () => (
  { children }
) => <div>{children}</div>);

jest.mock('foremanReact/components/common/SkeletonLoader', () => (
  { children }
) => <div>{children}</div>);

jest.mock('foremanReact/components/common/dates/RelativeDateTime', () => (
  { date, defaultValue }
) => <span>{date || defaultValue}</span>);

jest.mock('../CveFindingsModal', () => () => <div data-test="modal" />);

const { useAPI } = require('foremanReact/common/hooks/API/APIHooks');

describe('CveDetailsCard', () => {
  beforeEach(() => {
    useAPI.mockReset();
  });

  it('renders recent scans and findings', () => {
    const hostDetails = { id: 1 };
    const historyResponse = {
      results: [
        { id: 1, created_at: '2026-02-20', scanner: 'trivy', total: 10 },
        { id: 2, created_at: '2026-02-21', scanner: 'trivy', total: 12 },
        { id: 3, created_at: '2026-02-22', scanner: 'grype', total: 8 },
      ],
    };
    const latestResponse = {
      id: 3,
      created_at: '2026-02-22',
      scanner: 'grype',
      total: 8,
      summary: { worst: 'high' },
      critical: 1,
      high: 1,
      medium: 2,
      low: 4,
      findings: [
        {
          id: 'CVE-1',
          name: 'pkg',
          version: '1.0',
          severity: 'HIGH',
          published: '2026-02-10',
        },
      ],
    };

    useAPI.mockImplementation((_method, url) => {
      if (url && url.includes('/latest')) {
        return { response: latestResponse, status: 'RESOLVED' };
      }
      return { response: historyResponse, status: 'RESOLVED' };
    });

    const wrapper = mount(<CveDetailsCard hostDetails={hostDetails} />);

    expect(wrapper.find('table').length).toBeGreaterThan(0);
    expect(wrapper.text()).toContain('CVEs');
    expect(wrapper.text()).toContain('pkg');
  });

  it('falls back to history when latest is empty', () => {
    const hostDetails = { id: 1 };
    const historyResponse = {
      results: [{ id: 1, created_at: '2026-02-20', scanner: 'trivy', total: 10 }],
    };

    useAPI.mockImplementation((_method, url) => {
      if (url && url.includes('/latest')) {
        return { response: {}, status: 'RESOLVED' };
      }
      return { response: historyResponse, status: 'RESOLVED' };
    });

    const wrapper = mount(<CveDetailsCard hostDetails={hostDetails} />);
    expect(wrapper.text()).toContain('Report');
    expect(wrapper.text()).toContain('trivy');
  });

  it('prefers latest when present', () => {
    const hostDetails = { id: 1 };
    const historyResponse = {
      results: [{ id: 1, created_at: '2026-02-20', scanner: 'trivy', total: 10 }],
    };
    const latestResponse = {
      id: 2,
      created_at: '2026-02-21',
      scanner: 'grype',
      total: 8,
      summary: { worst: 'high' },
      findings: [],
    };

    useAPI.mockImplementation((_method, url) => {
      if (url && url.includes('/latest')) {
        return { response: latestResponse, status: 'RESOLVED' };
      }
      return { response: historyResponse, status: 'RESOLVED' };
    });

    const wrapper = mount(<CveDetailsCard hostDetails={hostDetails} />);
    expect(wrapper.text()).toContain('grype');
  });

  it('keeps unknown severities out of the preview when ranked CVEs exist', () => {
    const hostDetails = { id: 1 };
    const latestResponse = {
      id: 2,
      created_at: '2026-02-21',
      scanner: 'grype',
      total: 6,
      summary: { worst: 'critical' },
      findings: [
        {
          id: 'CVE-unknown',
          name: 'unknown-pkg',
          version: '1.0',
          severity: 'UNKNOWN',
          published: '2026-02-20',
        },
        {
          id: 'CVE-critical',
          name: 'critical-pkg',
          version: '1.0',
          severity: 'CRITICAL',
          published: '2026-02-10',
        },
        {
          id: 'CVE-high',
          name: 'high-pkg',
          version: '1.0',
          severity: 'HIGH',
          published: '2026-02-11',
        },
        {
          id: 'CVE-medium',
          name: 'medium-pkg',
          version: '1.0',
          severity: 'MEDIUM',
          published: '2026-02-12',
        },
        {
          id: 'CVE-low-a',
          name: 'low-a-pkg',
          version: '1.0',
          severity: 'LOW',
          published: '2026-02-13',
        },
        {
          id: 'CVE-low-b',
          name: 'low-b-pkg',
          version: '1.0',
          severity: 'LOW',
          published: '2026-02-14',
        },
      ],
    };

    useAPI.mockImplementation((_method, url) => {
      if (url && url.includes('/latest')) {
        return { response: latestResponse, status: 'RESOLVED' };
      }
      return { response: { results: [] }, status: 'RESOLVED' };
    });

    const wrapper = mount(<CveDetailsCard hostDetails={hostDetails} />);

    expect(wrapper.text()).toContain('critical-pkg');
    expect(wrapper.text()).toContain('low-b-pkg');
    expect(wrapper.text()).not.toContain('unknown-pkg');
    expect(wrapper.text()).toContain('More');
  });

  it('renders empty state when no scans', () => {
    const hostDetails = { id: 1 };
    useAPI.mockReturnValue({ response: null, status: 'RESOLVED' });

    const wrapper = mount(<CveDetailsCard hostDetails={hostDetails} />);
    expect(wrapper.text()).toContain('No CVE reports for this host');
  });
});
