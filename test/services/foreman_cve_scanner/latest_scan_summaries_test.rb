# frozen_string_literal: true

require 'test_plugin_helper'

module ForemanCveScanner
  class LatestScanSummariesTest < ActiveSupport::TestCase
    def setup
      @host = FactoryBot.create(:host)
      @other_host = FactoryBot.create(:host)
    end

    test 'call returns the latest scan summary for each requested host' do
      create_scan(host: @host, scanned_at: 2.hours.ago, total: 1, metrics: { low: 1 })
      latest_for_host = create_scan(host: @host, scanned_at: 1.hour.ago, total: 2, metrics: { high: 2 })
      latest_for_other_host = create_scan(
        host: @other_host,
        scanned_at: 30.minutes.ago,
        total: 3,
        metrics: { medium: 3 }
      )

      results = LatestScanSummaries.new(
        host_scope: Host::Base.where(id: [@host.id, @other_host.id]),
        host_ids: [@host.id, @other_host.id]
      ).call
      summaries = results.index_by { |row| row[:host_id] }

      assert_equal latest_for_host.id, summaries[@host.id][:id]
      assert_equal latest_for_other_host.id, summaries[@other_host.id][:id]
      assert_equal 2, summaries[@host.id][:total]
      assert_equal 3, summaries[@other_host.id][:total]
      assert_equal 3, summaries[@other_host.id][:medium]
    end

    test 'call ignores duplicate invalid and out of scope host ids' do
      latest_for_host = create_scan(host: @host, scanned_at: 1.hour.ago, total: 2, metrics: { high: 2 })
      create_scan(host: @other_host, scanned_at: 30.minutes.ago, total: 3, metrics: { medium: 3 })

      results = LatestScanSummaries.new(
        host_scope: Host::Base.where(id: @host.id),
        host_ids: [@host.id, @host.id, @other_host.id, 'nope', nil]
      ).call

      assert_equal 1, results.size
      assert_equal @host.id, results[0][:host_id]
      assert_equal latest_for_host.id, results[0][:id]
    end

    test 'call prefers higher id when scans share the same scanned_at' do
      timestamp = 1.hour.ago
      older_id_scan = create_scan(host: @host, scanned_at: timestamp, total: 1, metrics: { low: 1 })
      newer_id_scan = create_scan(host: @host, scanned_at: timestamp, total: 2, metrics: { high: 2 })

      results = LatestScanSummaries.new(
        host_scope: Host::Base.where(id: @host.id),
        host_ids: [@host.id]
      ).call

      assert_equal 1, results.size
      assert_equal newer_id_scan.id, results[0][:id]
      assert_operator newer_id_scan.id, :>, older_id_scan.id
    end

    private

    def create_scan(host:, scanned_at:, total:, metrics: {})
      critical = metrics.fetch(:critical, 0)
      high = metrics.fetch(:high, 0)
      medium = metrics.fetch(:medium, 0)
      low = metrics.fetch(:low, 0)

      ForemanCveScanner::CveScan.create!(
        host: host,
        scanner: 'trivy',
        source: 'rex',
        scanned_at: scanned_at,
        raw: { 'dummy' => true },
        summary: {
          'worst' => ForemanCveScanner::CveScan.worst_severity(
            'critical' => critical,
            'high' => high,
            'medium' => medium,
            'low' => low
          ),
        },
        findings: total.zero? ? [] : [{ 'id' => 'CVE-0000-0000' }],
        total: total,
        critical: critical,
        high: high,
        medium: medium,
        low: low
      )
    end
  end
end
