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
            scanned_at: '2026-05-14T10:00:00Z',
            total: 18,
            critical: 2,
            high: 4,
            medium: 5,
            low: 7,
          },
          {
            id: 11,
            scanned_at: '2026-05-10T10:00:00Z',
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
            scanned_at: '2026-05-14T10:00:00Z',
            total: 12,
            critical: 2,
            high: 3,
            medium: 3,
            low: 4,
          },
          {
            id: 1,
            scanned_at: '2026-05-10T10:00:00Z',
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

  it('renders compare mode controls and uses bar clicks for selection', () => {
    const onToggleSelection = jest.fn();
    const onToggleCompareMode = jest.fn();
    const onOpen = jest.fn();
    const wrapper = mount(
      <CveTrendChart
        scans={[
          {
            id: 2,
            scanned_at: '2026-05-14T10:00:00Z',
            total: 12,
            critical: 2,
            high: 3,
            medium: 3,
            low: 4,
          },
          {
            id: 1,
            scanned_at: '2026-05-10T10:00:00Z',
            total: 8,
            critical: 1,
            high: 1,
            medium: 2,
            low: 4,
          },
        ]}
        compareMode
        selectedScanIds={[2]}
        onOpen={onOpen}
        onToggleSelection={onToggleSelection}
        onToggleCompareMode={onToggleCompareMode}
      />
    );

    expect(wrapper.text()).toContain('Cancel compare');
    expect(wrapper.text()).toContain('1/2 selected');

    wrapper.find('button.cve-trend-bar-button').at(1).simulate('click');
    wrapper
      .find('button')
      .filterWhere(node => node.text() === 'Cancel compare')
      .first()
      .simulate('click');

    expect(onToggleSelection).toHaveBeenCalledWith(2);
    expect(onOpen).not.toHaveBeenCalled();
    expect(onToggleCompareMode).toHaveBeenCalled();
  });
});
