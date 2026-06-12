/* eslint-disable import/no-unresolved */
import React from 'react';
import { mount } from 'enzyme';
import { act } from 'react-dom/test-utils';
import CveSummaryCell from '../CveSummaryCell';
import { resetCveSummaryStore } from '../cve_summary_store';

jest.mock('../CveFindingsModal', () => () => null);

const flushBatch = () =>
  new Promise(resolve => {
    setTimeout(resolve, 0);
  });

describe('CveSummaryCell', () => {
  beforeEach(() => {
    resetCveSummaryStore();
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        results: [
          {
            id: 11,
            host_id: 1,
            total: 2,
            summary: { worst: 'high' },
          },
          {
            id: 22,
            host_id: 2,
            total: 0,
            summary: { worst: 'none' },
          },
        ],
      }),
    });
  });

  afterEach(() => {
    resetCveSummaryStore();
    delete global.fetch;
  });

  it('batches host summary requests across cells', async () => {
    let wrapper;

    await act(async () => {
      wrapper = mount(
        <div>
          <CveSummaryCell hostId={1} hostName="alpha" />
          <CveSummaryCell hostId={2} hostName="beta" />
        </div>
      );
      await flushBatch();
      await flushBatch();
    });
    wrapper.update();

    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(global.fetch.mock.calls[0][0]).toContain(
      '/api/v2/cve_scans/latest_by_hosts?'
    );
    expect(global.fetch.mock.calls[0][0]).toContain('host_ids%5B%5D=1');
    expect(global.fetch.mock.calls[0][0]).toContain('host_ids%5B%5D=2');
    expect(wrapper.text()).toContain('2');
    expect(wrapper.text()).toContain('0');
  });
});
