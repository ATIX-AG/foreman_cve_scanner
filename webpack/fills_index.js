/* eslint-disable import/no-unresolved */
import React from 'react';
import { addGlobalFill } from 'foremanReact/components/common/Fill/GlobalFill';
import { registerColumns } from 'foremanReact/components/HostsIndex/Columns/core';
import { translate as __ } from 'foremanReact/common/I18n';
import CveDetailsCard from './components/CveDetailsCard';
import CveScansTab from './components/CveScansTab';
import CveSummaryCell from './components/CveSummaryCell';

const DETAILS_CARD_WEIGHT = 2200;
const SCANS_TAB_WEIGHT = 450;

addGlobalFill(
  'host-tab-details-cards',
  'foreman-cve-scanner-details-card',
  <CveDetailsCard key="foreman-cve-scanner-details-card" />,
  DETAILS_CARD_WEIGHT
);

addGlobalFill(
  'host-details-page-tabs',
  'CVE scans',
  <CveScansTab key="foreman-cve-scanner-scans-tab" />,
  SCANS_TAB_WEIGHT,
  { title: __('CVE scans') }
);

registerColumns([
  {
    columnName: 'cve_findings',
    title: __('CVE'),
    wrapper: hostDetails => (
      <CveSummaryCell hostId={hostDetails?.id} hostName={hostDetails?.name} />
    ),
    weight: 450,
    tableName: 'hosts',
    categoryName: __('Security'),
    categoryKey: 'security',
    isSorted: false,
  },
]);
