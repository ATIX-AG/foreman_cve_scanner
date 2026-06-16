/* eslint-disable import/no-unresolved */
import React from 'react';
import { mount } from 'enzyme';
import { act } from 'react-dom/test-utils';
import CveFindingsView from '../CveFindingsView';

describe('CveFindingsView', () => {
  it('renders no reports state when scan is missing', () => {
    const wrapper = mount(
      <CveFindingsView scan={null} status="RESOLVED" initialFilter="all" />
    );

    expect(wrapper.text()).toContain('No CVE reports for this host');
    expect(wrapper.text()).toContain('Run a CVE scan to see results here.');
  });

  it('renders success state when scan has no findings', () => {
    const wrapper = mount(
      <CveFindingsView
        scan={{
          id: 1,
          scanned_at: '2026-02-22T10:00:00Z',
          scanner: 'trivy',
          source: 'rex',
          total: 0,
          findings: [],
        }}
        status="RESOLVED"
        initialFilter="all"
      />
    );

    expect(wrapper.text()).toContain('No CVEs found');
    expect(wrapper.text()).toContain(
      'The latest CVE scan found no vulnerabilities for this host.'
    );
  });

  it('filters findings by severity and search text', () => {
    const wrapper = mount(
      <CveFindingsView
        scan={{
          id: 1,
          scanned_at: '2026-02-22T10:00:00Z',
          scanner: 'trivy',
          source: 'rex',
          total: 2,
          findings: [
            {
              id: 'CVE-1',
              severity: 'HIGH',
              name: 'openssl',
              version: '1.1',
              title: 'OpenSSL issue',
            },
            {
              id: 'CVE-2',
              severity: 'LOW',
              name: 'curl',
              version: '8.0',
              title: 'Curl issue',
            },
          ],
        }}
        status="RESOLVED"
        initialFilter="all"
      />
    );

    const lowButton = wrapper
      .find('button')
      .filterWhere(node => node.text().toLowerCase() === 'low')
      .first();
    lowButton.simulate('click');
    wrapper.update();

    expect(wrapper.text()).toContain('CVE-2');
    expect(wrapper.text()).not.toContain('CVE-1');

    const allButton = wrapper
      .find('button')
      .filterWhere(node => node.text().toLowerCase() === 'all')
      .first();
    allButton.simulate('click');

    act(() => {
      wrapper.find('SearchInput').prop('onChange')('openssl');
    });
    wrapper.update();

    expect(wrapper.text()).toContain('CVE-1');
    expect(wrapper.text()).not.toContain('CVE-2');
  });
});
