# frozen_string_literal: true

require 'test_plugin_helper'

module ForemanCveScanner
  class ScanComparisonTest < ActiveSupport::TestCase
    def setup
      @host = FactoryBot.create(:host)
      @first_scan = create_scan(
        created_at: 2.hours.ago,
        findings: [
          finding('CVE-1', 'openssl', 'HIGH', '1.0'),
          finding('CVE-2', 'curl', 'LOW', '1.0'),
          finding('CVE-3', 'bash', 'MEDIUM', '1.0'),
        ]
      )
      @second_scan = create_scan(
        created_at: 1.hour.ago,
        findings: [
          finding('CVE-1', 'openssl', 'CRITICAL', '1.0'),
          finding('CVE-2', 'curl', 'LOW', '2.0'),
          finding('CVE-4', 'glibc', 'HIGH', '1.0'),
        ]
      )
    end

    test 'compare builds summary and result rows' do
      comparison = ScanComparison.compare(@first_scan, @second_scan)
      statuses = comparison[:results].to_h { |row| [row[:id], row] }

      assert_equal 1, comparison[:summary]['updated']
      assert_equal 1, comparison[:summary]['resolved']
      assert_equal 1, comparison[:summary]['new']
      assert_equal 'updated', statuses['CVE-1'][:status]
      assert_equal(
        { old: 'HIGH', new: 'CRITICAL' },
        statuses['CVE-1'][:diff]['severity']
      )
    end

    test 'compare includes previous and current scan metadata' do
      comparison = ScanComparison.compare(@first_scan, @second_scan)

      assert_equal @first_scan.id, comparison[:previous][:id]
      assert_equal @second_scan.id, comparison[:current][:id]
      assert_equal @first_scan.scanner, comparison[:previous][:scanner]
      assert_equal @second_scan.scanner, comparison[:current][:scanner]
    end

    private

    def finding(id, name, severity, version)
      {
        'id' => id,
        'name' => name,
        'severity' => severity,
        'version' => version,
      }
    end

    def create_scan(created_at:, findings:)
      ForemanCveScanner::CveScan.create!(
        host: @host,
        scanner: 'trivy',
        created_at: created_at,
        raw: { 'dummy' => true },
        summary: { 'worst' => 'high' },
        findings: findings,
        total: findings.size,
        critical: findings.count { |finding| finding['severity'] == 'CRITICAL' },
        high: findings.count { |finding| finding['severity'] == 'HIGH' },
        medium: findings.count { |finding| finding['severity'] == 'MEDIUM' },
        low: findings.count { |finding| finding['severity'] == 'LOW' }
      )
    end
  end
end
