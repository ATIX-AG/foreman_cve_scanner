/* eslint-disable import/no-unresolved */
import React from 'react';
import { mount } from 'enzyme';
import CveTrendChart from '../CveTrendChart';

describe('CveTrendChart', () => {
  it('renders the last scan summary and legend', () => {
    const wrapper = mount(
      <CveTrendChart
        scans={[
          {
            id: 12,
            created_at: '2026-05-14T10:00:00Z',
            total: 18,
            critical: 2,
            high: 4,
            medium: 5,
            low: 7,
          },
          {
            id: 11,
            created_at: '2026-05-10T10:00:00Z',
            total: 15,
            critical: 1,
            high: 3,
            medium: 5,
            low: 6,
          },
        ]}
      />
    );

    expect(wrapper.text()).toContain('Trend');
    expect(wrapper.text()).toContain('Last 2 scans');
    expect(wrapper.text()).toContain('Latest total');
    expect(wrapper.text()).toContain('18');
    expect(wrapper.text()).toContain('Critical');
    expect(wrapper.text()).toContain('Low');
  });

  it('opens the selected scan when a bar is clicked', () => {
    const onOpen = jest.fn();
    const wrapper = mount(
      <CveTrendChart
        scans={[
          {
            id: 2,
            created_at: '2026-05-14T10:00:00Z',
            total: 12,
            critical: 2,
            high: 3,
            medium: 3,
            low: 4,
          },
          {
            id: 1,
            created_at: '2026-05-10T10:00:00Z',
            total: 8,
            critical: 1,
            high: 1,
            medium: 2,
            low: 4,
          },
        ]}
        onOpen={onOpen}
      />
    );

    wrapper.find('button.cve-trend-bar-button').at(0).simulate('click');

    expect(onOpen).toHaveBeenCalledWith(1);
  });
});
