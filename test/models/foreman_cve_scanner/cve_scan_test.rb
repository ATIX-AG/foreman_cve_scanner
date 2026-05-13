# frozen_string_literal: true

require 'test_plugin_helper'

module ForemanCveScanner
  class CveScanTest < ActiveSupport::TestCase
    def setup
      @host = FactoryBot.create(:host)
    end

    test 'is invalid without required host and scanner attributes' do
      scan = CveScan.new

      assert_not scan.valid?
      assert_includes scan.errors.attribute_names, :host_id
      assert_includes scan.errors.attribute_names, :scanner
    end

    test 'is invalid without required scan payload attributes' do
      scan = CveScan.new

      assert_not scan.valid?
      assert_includes scan.errors.attribute_names, :raw
      assert_includes scan.errors.attribute_names, :summary
      assert_includes scan.errors.attribute_names, :findings
    end

    test 'for_host returns only scans for the given host' do
      other_host = FactoryBot.create(:host)
      host_scan = create_scan(host: @host, total: 1)
      other_scan = create_scan(host: other_host, total: 2)

      result = CveScan.for_host(@host.id)

      assert_includes result, host_scan
      assert_not_includes result, other_scan
    end

    test 'recent_first orders by created_at desc and id desc' do
      older = create_scan(host: @host, created_at: 2.hours.ago)
      newer = create_scan(host: @host, created_at: 1.hour.ago)
      timestamp = Time.zone.parse('2026-05-13 10:00:00')
      same_time_a = create_scan(host: @host, created_at: timestamp)
      same_time_b = create_scan(host: @host, created_at: timestamp)

      result = CveScan.recent_first.to_a

      assert_operator result.index(newer), :<, result.index(older)
      assert_operator result.index(same_time_b), :<, result.index(same_time_a)
    end

    test 'destroying a host destroys its cve scans' do
      create_scan(host: @host, total: 1)
      create_scan(host: @host, total: 2)

      assert_difference('ForemanCveScanner::CveScan.count', -2) do
        @host.destroy
      end
    end

    private

    def create_scan(host:, created_at: Time.current, total: 0)
      CveScan.create!(
        host: host,
        scanner: 'trivy',
        created_at: created_at,
        raw: { 'dummy' => true },
        summary: { 'worst' => 'low' },
        findings: [{ 'id' => 'CVE-0000-0000' }],
        total: total,
        critical: 0,
        high: 0,
        medium: 0,
        low: total
      )
    end
  end
end
