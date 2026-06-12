/* eslint-disable import/no-unresolved */
import { foremanUrl } from 'foremanReact/common/helpers';

const listeners = new Map();
const cache = new Map();
const pendingHostIds = new Set();
let flushScheduled = false;

const notify = (hostId, value) => {
  const hostListeners = listeners.get(hostId) || new Set();
  hostListeners.forEach(listener => listener(value));
};

const storeValue = (hostId, value) => {
  cache.set(hostId, value);
  notify(hostId, value);
};

const flushPending = async () => {
  flushScheduled = false;
  const hostIds = [...pendingHostIds];
  pendingHostIds.clear();
  if (!hostIds.length) return;

  const params = new URLSearchParams();
  hostIds.forEach(hostId => params.append('host_ids[]', hostId));

  try {
    const response = await fetch(
      foremanUrl(`/api/v2/cve_scans/latest_by_hosts?${params.toString()}`),
      { credentials: 'same-origin' }
    );
    if (!response.ok) throw new Error('Failed to load CVE summaries');

    const payload = await response.json();
    const results = Array.isArray(payload?.results) ? payload.results : [];
    const byHostId = new Map(results.map(result => [result.host_id, result]));

    hostIds.forEach(hostId => {
      storeValue(hostId, byHostId.get(hostId) || null);
    });
  } catch (_error) {
    hostIds.forEach(hostId => {
      storeValue(hostId, null);
    });
  }
};

const scheduleFlush = () => {
  if (flushScheduled) return;

  flushScheduled = true;
  setTimeout(() => {
    flushPending();
  }, 0);
};

const enqueueHostId = hostId => {
  if (cache.has(hostId) || pendingHostIds.has(hostId)) return;

  pendingHostIds.add(hostId);
  scheduleFlush();
};

export const subscribeToCveSummary = (hostId, listener) => {
  if (!listeners.has(hostId)) listeners.set(hostId, new Set());
  listeners.get(hostId).add(listener);

  if (cache.has(hostId)) {
    listener(cache.get(hostId));
  } else {
    enqueueHostId(hostId);
  }

  return () => {
    const hostListeners = listeners.get(hostId);
    if (!hostListeners) return;

    hostListeners.delete(listener);
    if (!hostListeners.size) listeners.delete(hostId);
  };
};

export const getCachedCveSummary = hostId => cache.get(hostId);

export const resetCveSummaryStore = () => {
  listeners.clear();
  cache.clear();
  pendingHostIds.clear();
  flushScheduled = false;
};
