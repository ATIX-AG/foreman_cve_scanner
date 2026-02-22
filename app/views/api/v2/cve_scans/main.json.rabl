# frozen_string_literal: true

object @cve_scan

extends 'api/v2/cve_scans/base'

attributes :findings, :created_at, :updated_at
