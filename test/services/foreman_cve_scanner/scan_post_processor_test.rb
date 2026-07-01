# frozen_string_literal: true

require 'test_plugin_helper'

module ForemanCveScanner
  class ScanPostProcessorTest < ActiveSupport::TestCase
    def setup
      @host = FactoryBot.create(:host)
      @previous_retention = Setting[:cve_scan_delete_after_days]
    end

    def teardown
      Setting[:cve_scan_delete_after_days] = @previous_retention
    end

    test 'refreshes cve host status' do
      create_scan(critical: 1)

      assert_difference('HostStatus::CveStatus.count', 1) do
        ScanPostProcessor.new(@host).call
      end

      status = HostStatus::CveStatus.find_by(host: @host)
      assert_equal HostStatus::CveStatus::CVE_SCANNER_STATUS_CRITICAL_HIGH, status.status
    end

    test 'cleans up old scans for host using retention setting' do
      Setting[:cve_scan_delete_after_days] = 1
      old_scan = create_scan(scanned_at: 3.days.ago)
      kept_scan = create_scan(scanned_at: Time.current)

      ScanPostProcessor.new(@host).call

      assert_not CveScan.exists?(old_scan.id)
      assert CveScan.exists?(kept_scan.id)
    end

    private

    def create_scan(options = {})
      critical = options.fetch(:critical, 0)
      scanned_at = options.fetch(:scanned_at, Time.current)
      CveScan.create!(
        host: @host,
        scanner: 'trivy',
        source: 'rex',
        scanned_at: scanned_at,
        raw: { 'dummy' => true },
        summary: { 'worst' => critical.positive? ? 'critical' : 'none' },
        findings: critical.positive? ? [{ 'id' => 'CVE-0000-0000' }] : [],
        total: critical,
        critical: critical,
        high: 0,
        medium: 0,
        low: 0
      )
    end
  end
end
