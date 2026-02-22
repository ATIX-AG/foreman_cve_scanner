/* eslint-disable import/no-unresolved */
import React from 'react';
import { mount } from 'enzyme';
import CveFindingsModal from '../CveFindingsModal';

jest.mock('foremanReact/common/hooks/API/APIHooks', () => ({
  useAPI: jest.fn(),
}));

const { useAPI } = require('foremanReact/common/hooks/API/APIHooks');

describe('CveFindingsModal', () => {
  beforeEach(() => {
    useAPI.mockReset();
  });

  it('filters findings by severity', () => {
    useAPI.mockReturnValue({
      response: {
        id: 1,
        created_at: '2026-02-22T10:00:00Z',
        total: 2,
        findings: [
          { id: 'CVE-1', severity: 'HIGH', name: 'a', version: '1' },
          { id: 'CVE-2', severity: 'LOW', name: 'b', version: '2' },
        ],
      },
      status: 'RESOLVED',
    });

    const wrapper = mount(
      <CveFindingsModal
        isOpen
        onClose={() => {}}
        hostId={1}
        scanId={1}
        initialFilter="all"
      />
    );

    expect(wrapper.text()).toContain('CVE-1');
    expect(wrapper.text()).toContain('CVE-2');

    const lowButton = wrapper
      .find('button')
      .filterWhere(node => node.text().toLowerCase() === 'low')
      .first();
    lowButton.simulate('click');
    wrapper.update();

    expect(wrapper.text()).toContain('CVE-2');
    expect(wrapper.text()).not.toContain('CVE-1');
  });

  it('shows empty state when no findings', () => {
    useAPI.mockReturnValue({
      response: {
        id: 1,
        created_at: '2026-02-22T10:00:00Z',
        total: 0,
        findings: [],
      },
      status: 'RESOLVED',
    });

    const wrapper = mount(
      <CveFindingsModal
        isOpen
        onClose={() => {}}
        hostId={1}
        scanId={1}
        initialFilter="all"
      />
    );

    expect(wrapper.text()).toContain('No findings for selected filter');
  });
});
