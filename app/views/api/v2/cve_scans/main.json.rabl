# frozen_string_literal: true

object @cve_scan

extends 'api/v2/cve_scans/base'

attributes :updated_at

node(:findings) { |scan| @cve_scan_findings || scan.findings }
