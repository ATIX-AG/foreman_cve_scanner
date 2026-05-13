# ForemanCveScanner

Plugin to:
1. install Trivy/Grype on a host using Foreman Remote Execution (REX)
2. run CVE scans via REX and parse the results
3. store scan history per host in a dedicated table
4. expose scan data via API
5. show CVE findings in the Host details UI
6. show summary status in the Hosts list

## Features

- Support for Trivy and Grype scanners
- REX job templates for installing and running CVE scans
- JSON output parsing with robust handling of chunked stdout
- Per-host scan history with totals and severity counts
- API endpoints for scan history and latest scan
- Host Details card with findings and modal view
- Host Details tab “CVE scans” for full history
- Hosts overview list column “CVE” with quick summary and modal
- Integrated in the Host Status
- Export scan results as CSV

## Installation

See [How_to_Install_a_Plugin](http://projects.theforeman.org/projects/foreman/wiki/How_to_Install_a_Plugin)
for how to install Foreman plugins

## Usage

- Run the REX job to install Trivy and/or Grype
- Run the REX job to scan a host
- You can configure recurring CVE scans via `Monitor -> Jobs`
- View results in:
  - Hosts overview list column “CVE” (use 'Manage Columns' to enable)
  - Host Details card and modal
  - Host Details tab “CVE scans”

## TODO

- Deliver Trivy/Grype via Katello

## Contributing

Fork and send a Pull Request. Thanks!

## Copyright

Copyright (c) 2024 Bernhard Suttner / ATIX AG

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
