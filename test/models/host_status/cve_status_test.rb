# frozen_string_literal: true

require 'test_plugin_helper'

module HostStatus
  class CveStatusTest < ActiveSupport::TestCase
    def setup
      @host = FactoryBot.create(:host)
    end

    test 'no scans returns warning status' do
      status = @host.get_status(HostStatus::CveStatus)
      assert_equal 'No CVE scans', status.to_label
      assert_equal HostStatus::Global::WARN, status.to_global
      assert_equal 0, status.to_status
    end

    test 'critical or high scan returns error status' do
      create_scan(critical: 1, high: 0, medium: 0, low: 0)
      status = @host.get_status(HostStatus::CveStatus)
      assert_equal 'Critical or high CVEs', status.to_label
      assert_equal HostStatus::Global::ERROR, status.to_global
      assert_equal 3, status.to_status
    end

    test 'medium scan returns warn status' do
      create_scan(critical: 0, high: 0, medium: 2, low: 0)
      status = @host.get_status(HostStatus::CveStatus)
      assert_equal 'Medium CVEs', status.to_label
      assert_equal HostStatus::Global::WARN, status.to_global
      assert_equal 2, status.to_status
    end

    test 'low scan returns ok status' do
      create_scan(critical: 0, high: 0, medium: 0, low: 1)
      status = @host.get_status(HostStatus::CveStatus)
      assert_equal 'Low CVEs', status.to_label
      assert_equal HostStatus::Global::OK, status.to_global
      assert_equal 1, status.to_status
    end

    test 'status is registered in registry' do
      assert_includes HostStatus.status_registry, HostStatus::CveStatus
    end

    private

    def create_scan(critical:, high:, medium:, low:)
      total = critical + high + medium + low
      ForemanCveScanner::CveScan.create!(
        host: @host,
        scanner: 'trivy',
        created_at: Time.now.utc,
        raw: { 'dummy' => true },
        summary: { 'worst' => 'low' },
        findings: [{ 'id' => 'CVE-0000-0000' }],
        total: total,
        critical: critical,
        high: high,
        medium: medium,
        low: low
      )
    end
  end
end
