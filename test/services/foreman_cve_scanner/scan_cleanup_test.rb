# frozen_string_literal: true

require 'test_plugin_helper'

module ForemanCveScanner
  class ScanCleanupTest < ActiveSupport::TestCase
    def setup
      @host = FactoryBot.create(:host)
      @previous_setting = Setting[:cve_scan_delete_after_days]
    end

    def teardown
      Setting[:cve_scan_delete_after_days] = @previous_setting
    end

    test 'cleanup! does nothing when retention is disabled' do
      Setting[:cve_scan_delete_after_days] = 0
      old_scan = create_scan(10.days.ago)

      deleted = ScanCleanup.new(scope: @host.cve_scans).cleanup!

      assert_equal 0, deleted
      assert ForemanCveScanner::CveScan.exists?(old_scan.id)
    end

    test 'cleanup! removes scans older than configured retention' do
      Setting[:cve_scan_delete_after_days] = 5
      old_scan = create_scan(10.days.ago)
      recent_scan = create_scan(2.days.ago)

      deleted = ScanCleanup.new(scope: @host.cve_scans).cleanup!

      assert_equal 1, deleted
      assert_not ForemanCveScanner::CveScan.exists?(old_scan.id)
      assert ForemanCveScanner::CveScan.exists?(recent_scan.id)
    end

    test 'cleanup! uses explicit day override' do
      Setting[:cve_scan_delete_after_days] = 30
      old_scan = create_scan(10.days.ago)
      recent_scan = create_scan(2.days.ago)

      deleted = ScanCleanup.new(scope: @host.cve_scans, days: 5).cleanup!

      assert_equal 1, deleted
      assert_not ForemanCveScanner::CveScan.exists?(old_scan.id)
      assert ForemanCveScanner::CveScan.exists?(recent_scan.id)
    end

    private

    def create_scan(scanned_at)
      ForemanCveScanner::CveScan.create!(
        host: @host,
        scanner: 'trivy',
        source: 'rex',
        scanned_at: scanned_at,
        raw: { 'dummy' => true },
        summary: { 'worst' => 'low' },
        findings: [{ 'id' => 'CVE-0000-0000' }],
        total: 1,
        critical: 0,
        high: 0,
        medium: 0,
        low: 1
      )
    end
  end
end
