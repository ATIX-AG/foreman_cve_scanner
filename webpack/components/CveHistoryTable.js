/* eslint-disable import/no-unresolved */
import React from 'react';
import PropTypes from 'prop-types';
import { Table, Thead, Tbody, Tr, Th, Td } from '@patternfly/react-table';
import { Button } from '@patternfly/react-core';
import { translate as __ } from 'foremanReact/common/I18n';
import RelativeDateTime from 'foremanReact/components/common/dates/RelativeDateTime';

const CveHistoryTable = ({ scans, onOpen }) => (
  <Table
    variant="compact"
    aria-label="CVE scan history table"
    ouiaId="cve-details-history-table"
  >
    <Thead>
      <Tr ouiaId="cve-details-history-header">
        <Th>{__('Reported at')}</Th>
        <Th>{__('Scanner')}</Th>
        <Th>{__('Total')}</Th>
      </Tr>
    </Thead>
    <Tbody>
      {scans.map((scan, index) => (
        <Tr key={scan.id} ouiaId={`cve-details-history-row-${index}`}>
          <Td dataLabel={__('Reported at')}>
            <Button
              variant="link"
              className="cve-summary-link"
              onClick={() => onOpen(scan.id, 'all')}
              ouiaId={`cve-details-history-open-${scan.id}`}
            >
              <RelativeDateTime
                date={scan.created_at}
                defaultValue={__('Unknown time')}
              />
            </Button>
          </Td>
          <Td dataLabel={__('Scanner')}>{scan.scanner}</Td>
          <Td dataLabel={__('Total')}>{scan.total}</Td>
        </Tr>
      ))}
    </Tbody>
  </Table>
);

CveHistoryTable.propTypes = {
  scans: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.number.isRequired,
      created_at: PropTypes.string,
      scanner: PropTypes.string,
      total: PropTypes.number,
    })
  ).isRequired,
  onOpen: PropTypes.func.isRequired,
};

export default CveHistoryTable;
