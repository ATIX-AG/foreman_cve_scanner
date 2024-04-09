# ForemanCveScanner

Plugin to 
1. install trivy/grype CVE scanners on a host using a Foreman Remote Execution (REX) job
2. run a CVE scan using a REX job, collect the output and generate a Config Report
   
   ![image](https://github.com/ATIX-AG/foreman_cve_scanner/assets/25485845/85e3b676-7d90-41e5-bea5-7e0b5f4a685c)


*Introdction here*

## Installation

See [How_to_Install_a_Plugin](http://projects.theforeman.org/projects/foreman/wiki/How_to_Install_a_Plugin)
for how to install Foreman plugins

## Usage

- Run the REX job to install trivy and/or grype
- Run the REX job to scan a host
- Go to the Config Report page for a host to view the scan report

## TODO

- Better possiblities to filter the Config Report (maybe an extension to ConfigReport in Foreman)
- Have a scheduled REX Job to scan the hosts
- Make it visible on the Host Details page or on Foreman directly, if a high priority CVE on a host occurs
- Export a CVE scan
- Deliver trivy / grype via Katello
- More tests
- API

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

