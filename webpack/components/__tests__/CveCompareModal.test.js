/* eslint-disable import/no-unresolved */
import React from 'react';
import { mount } from 'enzyme';
import CveCompareModal from '../CveCompareModal';

jest.mock('foremanReact/common/hooks/API/APIHooks', () => ({
  useAPI: jest.fn(),
}));

const { useAPI } = require('foremanReact/common/hooks/API/APIHooks');

describe('CveCompareModal', () => {
  beforeEach(() => {
    useAPI.mockReset();
  });

  it('renders comparison summary and filters rows by status', () => {
    useAPI.mockReturnValue({
      response: {
        previous: {
          id: 1,
          scanned_at: '2026-02-20T10:00:00Z',
          scanner: 'trivy',
          source: 'rex',
        },
        current: {
          id: 2,
          scanned_at: '2026-02-21T10:00:00Z',
          scanner: 'grype',
          source: 'external',
        },
        summary: {
          new: 1,
          resolved: 1,
          updated: 1,
          unchanged: 0,
        },
        results: [
          {
            key: 'CVE-1::pkg-a',
            status: 'updated',
            id: 'CVE-1',
            name: 'pkg-a',
            severity: 'CRITICAL',
            version: '1.0',
            fixed: 'open',
            scan_status: 'affected',
            diff: {
              severity: { old: 'HIGH', new: 'CRITICAL' },
            },
          },
          {
            key: 'CVE-2::pkg-b',
            status: 'resolved',
            id: 'CVE-2',
            name: 'pkg-b',
            severity: 'LOW',
            version: '1.0',
            fixed: 'open',
            scan_status: 'affected',
            diff: {},
          },
          {
            key: 'CVE-3::pkg-c',
            status: 'new',
            id: 'CVE-3',
            name: 'pkg-c',
            severity: 'MEDIUM',
            version: '1.0',
            fixed: '2.0',
            scan_status: 'affected',
            diff: {},
          },
        ],
      },
      status: 'RESOLVED',
    });

    const wrapper = mount(
      <CveCompareModal
        hostId={1}
        isOpen
        onClose={() => {}}
        scanIds={[1, 2]}
      />
    );

    expect(wrapper.text()).toContain('Compare CVE reports');
    expect(wrapper.text()).toContain('Updated');
    expect(wrapper.text()).toContain('Resolved');
    expect(wrapper.text()).toContain('New');
    expect(wrapper.text()).toContain('Severity: HIGH -> CRITICAL');

    wrapper
      .find('button')
      .filterWhere(node => node.text() === 'Resolved')
      .last()
      .simulate('click');
    wrapper.update();

    expect(wrapper.text()).toContain('CVE-2');
    expect(wrapper.text()).not.toContain('CVE-3');
  });
});
