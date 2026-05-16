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
- API endpoint to push external CVE scans
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
- You can configure the default scanner for the `Run CVE scanner` template via `Administer -> Settings -> CVE Scanner -> Preferred CVE scanner`
- View results in:
  - Hosts overview list column “CVE” (use 'Manage Columns' to enable)
  - Host Details card and modal
  - Host Details tab “CVE scans”

## External Push API

Push a normalized CVE scan for a host with:

- `POST /api/v2/hosts/:host_id/cve_scans/import`

Required permission:

- `import_cve_scans`

Required payload structure:

```json
{
  "cve_scan": {
    "scanner": "custom-scanner",
    "source": "external",
    "scanned_at": "2026-05-14T08:00:00Z",
    "findings": [
      {
        "id": "CVE-2024-8373",
        "name": "angular",
        "severity": "LOW",
        "version": "1.8.2",
        "fixed": "open",
        "status": "affected",
        "title": "angular: From NVD collector",
        "published": "2024-09-09T15:15:12.887Z",
        "url": "https://avd.aquasec.com/nvd/cve-2024-8373"
      },
      {
        "id": "CVE-2024-9991",
        "name": "openssl",
        "severity": "CRITICAL",
        "version": "3.0.1",
        "fixed": "3.0.8",
        "status": "affected",
        "title": "openssl: Example critical issue",
        "published": "2024-10-01T10:00:00Z",
        "url": "https://example.test/CVE-2024-9991"
      },
      {
        "id": "CVE-2024-9992",
        "name": "curl",
        "severity": "HIGH",
        "version": "8.5.0",
        "fixed": "8.5.1",
        "status": "affected",
        "title": "curl: Example high issue",
        "published": "2024-10-02T10:00:00Z",
        "url": "https://example.test/CVE-2024-9992"
      },
      {
        "id": "CVE-2024-9993",
        "name": "tar",
        "severity": "MEDIUM",
        "version": "1.35",
        "fixed": "1.36",
        "status": "affected",
        "title": "tar: Example medium issue",
        "published": "2024-10-03T10:00:00Z",
        "url": "https://example.test/CVE-2024-9993"
      }
    ]
  }
}
```

Notes:

- `scanner` is a free-form producer name and can be an unknown external tool
- `source` is stored and shown in the UI, for example `external`
- `scanned_at` is required and is the only scan timestamp used in the UI
- `summary` and severity counters are calculated on the server from `findings`
- `raw` is not part of the public API contract

## Retention

You can configure automatic CVE scan cleanup with the plugin setting:

- `Administer -> Settings -> CVE Scanner -> Delete CVE scans after X days`

Behavior:

- `0` disables automatic cleanup
- scans older than the configured number of days are deleted
- the cleanup runs after imports and can also be triggered manually

Manual cleanup task:

- `bundle exec rake foreman_cve_scanner:cleanup_scans`

Override the configured retention for one run:

- `bundle exec rake foreman_cve_scanner:cleanup_scans DAYS=30`

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
