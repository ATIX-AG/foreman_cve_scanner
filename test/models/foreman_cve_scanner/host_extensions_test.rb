# frozen_string_literal: true

require 'test_plugin_helper'

module ForemanCveScanner
  class HostExtensionsTest < ActiveSupport::TestCase
    def setup
      @host = FactoryBot.create(:host)
      @other_host = FactoryBot.create(:host)
    end

    test 'cve_scanned finds hosts with or without scans' do
      create_scan(host: @host)

      assert_search_includes('cve_scanned = true', @host)
      assert_search_excludes('cve_scanned = true', @other_host)
      assert_search_includes('cve_scanned = false', @other_host)
      assert_search_excludes('cve_scanned = false', @host)
    end

    test 'severity and total searches use latest scan only' do
      create_scan(host: @host, scanned_at: 2.hours.ago, total: 7, critical: 1, high: 2, medium: 3, low: 1)
      create_scan(host: @host, scanned_at: 1.hour.ago, total: 0)
      create_scan(host: @other_host, total: 6, critical: 1, high: 1, medium: 2, low: 2)

      %w[total critical high medium low].each do |column|
        assert_search_includes("cve_#{column} > 0", @other_host)
        assert_search_excludes("cve_#{column} > 0", @host)
      end
    end

    test 'scanner and source searches use latest scan only' do
      create_scan(host: @host, scanned_at: 2.hours.ago, scanner: 'trivy', source: 'rex')
      create_scan(host: @host, scanned_at: 1.hour.ago, scanner: 'grype', source: 'external')
      create_scan(host: @other_host, scanner: 'trivy', source: 'rex')

      assert_search_includes('cve_scanner = trivy', @other_host)
      assert_search_excludes('cve_scanner = trivy', @host)
      assert_search_includes('cve_source = rex', @other_host)
      assert_search_excludes('cve_source = rex', @host)
    end

    test 'scanned_at search uses latest scan only' do
      cutoff = Time.zone.parse('2026-06-01 12:00:00')
      create_scan(host: @host, scanned_at: cutoff - 1.day)
      create_scan(host: @other_host, scanned_at: cutoff + 1.day)

      assert_search_includes("cve_scanned_at > \"#{cutoff.iso8601}\"", @other_host)
      assert_search_excludes("cve_scanned_at > \"#{cutoff.iso8601}\"", @host)
    end

    test 'rejects unsupported SQL operators' do
      assert_raises ::ScopedSearch::QueryNotSupported do
        ::Host::Managed.search_by_cve_total('cve_total', '>= 0) OR 1=1 --', '0')
      end
    end

    private

    def assert_search_includes(query, host)
      assert_includes search_host_ids(query), host.id
    end

    def assert_search_excludes(query, host)
      assert_not_includes search_host_ids(query), host.id
    end

    def search_host_ids(query)
      ::Host::Managed.search_for(query).pluck(:id)
    end

    def create_scan(host:, scanned_at: Time.current, scanner: 'trivy', source: 'rex', **counts)
      counts = { total: 0, critical: 0, high: 0, medium: 0, low: 0 }.merge(counts)

      CveScan.create!(
        host: host,
        scanner: scanner,
        source: source,
        scanned_at: scanned_at,
        raw: { 'dummy' => true },
        summary: { 'worst' => CveScan.worst_severity(counts.transform_keys(&:to_s)) },
        findings: counts[:total].zero? ? [] : [{ 'id' => 'CVE-0000-0000' }],
        total: counts[:total],
        critical: counts[:critical],
        high: counts[:high],
        medium: counts[:medium],
        low: counts[:low]
      )
    end
  end
end
