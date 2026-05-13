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
    useAPI.mockImplementation((_method, url) => {
      if (url && url.includes('/cve_scans/1')) {
        return {
          response: {
            id: 1,
            created_at: '2026-02-20T10:00:00Z',
            scanner: 'trivy',
            findings: [
              { id: 'CVE-1', name: 'pkg-a', severity: 'HIGH', version: '1.0' },
              { id: 'CVE-2', name: 'pkg-b', severity: 'LOW', version: '1.0' },
            ],
          },
          status: 'RESOLVED',
        };
      }

      return {
        response: {
          id: 2,
          created_at: '2026-02-21T10:00:00Z',
          scanner: 'grype',
          findings: [
            { id: 'CVE-1', name: 'pkg-a', severity: 'CRITICAL', version: '1.0' },
            { id: 'CVE-3', name: 'pkg-c', severity: 'MEDIUM', version: '1.0' },
          ],
        },
        status: 'RESOLVED',
      };
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
    expect(wrapper.text()).toContain('Severity changed');
    expect(wrapper.text()).toContain('Resolved');
    expect(wrapper.text()).toContain('New');

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
