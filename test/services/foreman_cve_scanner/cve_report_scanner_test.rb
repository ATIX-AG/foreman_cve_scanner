# frozen_string_literal: true

require 'test_plugin_helper'

module ForemanCveScanner
  class CveReportScannerTest < ActiveSupport::TestCase
    test 'should identify as cve scan' do
      raw = {
        'reporter' => 'cve_scan',
        'scan' => JSON.parse(File.read(File.join(ForemanCveScanner::Engine.root, 'test/fixtures/grype.json'))),
      }
      assert_equal('CveScanner', ForemanCveScanner::CveReportScanner.identify_origin(raw))
    end

    test 'should raise an exception if invalid report' do
      assert_raise Foreman::Exception do
        @scanner = ForemanCveScanner::CveReportScanner.new({})
      end
    end

    test 'trivy scan has valid data' do
      data = JSON.parse(File.read(File.join(ForemanCveScanner::Engine.root, 'test/fixtures/trivy.json')))
      scanner = ForemanCveScanner::CveReportScanner.new('scan' => data)
      scanner.generate
      assert_equal(trivy_vulnerability_count(data), scanner.logs.count)
      assert_equal('info', scanner.logs[0]['log']['level'])
      expected_message = [
        'CVE-2020-12762: json-c, libfastjson: integer overflow and out-of-',
        'bounds write via a large JSON file # url: ',
        'https://avd.aquasec.com/nvd/cve-2020-12762',
      ].join
      assert_equal scanner.logs[0]['log']['messages']['message'], expected_message
    end

    test 'grype scan has valid data' do
      data = JSON.parse(File.read(File.join(ForemanCveScanner::Engine.root, 'test/fixtures/grype.json')))
      scanner = ForemanCveScanner::CveReportScanner.new('scan' => data)
      scanner.generate
      assert_equal(Array(data['matches']).size, scanner.logs.count)
      first_severity = data.dig('matches', 0, 'vulnerability', 'severity')
      expected_level = expected_level_for(first_severity)
      assert_equal scanner.logs[0]['log']['level'], expected_level
      expected_message = [
        'CVE-2007-0086: The Apache HTTP Server, when accessed through a TCP ',
        'connection with a large window size, allows remote attackers to cause ',
        'a denial of service (network bandwidth consumption) via a Range header ',
        'that specifies multiple copies of the same fragment. # url: ',
        'https://nvd.nist.gov/vuln/detail/CVE-2007-0086',
      ].join
      assert_equal scanner.logs[0]['log']['messages']['message'], expected_message
    end

    test 'detect_scanner returns expected scanner names' do
      assert_equal 'grype', ForemanCveScanner::CveReportScanner.detect_scanner('matches' => [])
      assert_equal 'trivy', ForemanCveScanner::CveReportScanner.detect_scanner('Results' => [])
      assert_equal 'unknown', ForemanCveScanner::CveReportScanner.detect_scanner('foo' => 'bar')
    end

    test 'trivy scan keeps duplicate cves for different packages' do
      data = {
        'Results' => [
          {
            'Vulnerabilities' => [
              {
                'VulnerabilityID' => 'CVE-2026-0001',
                'PkgName' => 'openssl',
                'InstalledVersion' => '1.0',
                'Title' => 'openssl issue',
                'Severity' => 'HIGH',
                'PrimaryURL' => 'https://example.com/openssl',
              },
              {
                'VulnerabilityID' => 'CVE-2026-0001',
                'PkgName' => 'curl',
                'InstalledVersion' => '2.0',
                'Title' => 'curl issue',
                'Severity' => 'MEDIUM',
                'PrimaryURL' => 'https://example.com/curl',
              },
            ],
          },
        ],
      }

      scanner = ForemanCveScanner::CveReportScanner.new('scan' => data)
      finding_names = scanner.unified_vulnerabilities.map { |finding| finding['name'] }

      assert_equal 2, scanner.unified_vulnerabilities.size
      assert_equal %w[openssl curl], finding_names

      scanner.generate

      assert_equal 2, scanner.logs.count
      assert_equal 1, scanner.metrics['high']
      assert_equal 1, scanner.metrics['medium']
      assert_equal 2, scanner.metrics['total']
    end

    test 'grype scan keeps duplicate cves for different packages' do
      data = {
        'matches' => [
          {
            'artifact' => { 'name' => 'openssl', 'version' => '1.0' },
            'vulnerability' => {
              'id' => 'CVE-2026-0002',
              'description' => 'openssl issue',
              'severity' => 'HIGH',
              'dataSource' => 'https://example.com/openssl',
            },
          },
          {
            'artifact' => { 'name' => 'curl', 'version' => '2.0' },
            'vulnerability' => {
              'id' => 'CVE-2026-0002',
              'description' => 'curl issue',
              'severity' => 'LOW',
              'dataSource' => 'https://example.com/curl',
            },
          },
        ],
      }

      scanner = ForemanCveScanner::CveReportScanner.new('scan' => data)
      finding_names = scanner.unified_vulnerabilities.map { |finding| finding['name'] }

      assert_equal 2, scanner.unified_vulnerabilities.size
      assert_equal %w[openssl curl], finding_names

      scanner.generate

      assert_equal 2, scanner.logs.count
      assert_equal 1, scanner.metrics['high']
      assert_equal 1, scanner.metrics['low']
      assert_equal 2, scanner.metrics['total']
    end

    private

    def trivy_vulnerability_count(data)
      Array(data['Results']).sum do |result|
        Array(result['Vulnerabilities']).size
      end
    end

    def expected_level_for(severity)
      map = {
        'CRITICAL' => 'err',
        'HIGH' => 'warning',
        'MEDIUM' => 'info',
        'LOW' => 'debug',
      }
      map.fetch(severity.to_s.strip.upcase, 'info')
    end
  end
end
