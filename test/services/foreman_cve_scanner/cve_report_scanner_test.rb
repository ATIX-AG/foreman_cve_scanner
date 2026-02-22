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
      assert_equal(10, scanner.logs.count)
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
      assert_equal(18, scanner.logs.count)
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

    private

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
