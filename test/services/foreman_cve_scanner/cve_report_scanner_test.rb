require 'test_plugin_helper'

module ForemanCveScanner
  class CveReportScannerTest < ActiveSupport::TestCase
    test 'should identify as cve scan' do
      raw = {
        'reporter' => 'cve_scan',
        'scan' => JSON.parse(File.read(File.join(ForemanCveScanner::Engine.root, 'test/fixtures/grype.json')))
      }
      assert_equal ForemanCveScanner::CveReportScanner.identify_origin(raw), 'CveScanner'
    end

    test 'should raise an exception if invalid report' do
      assert_raise Foreman::Exception do
        @scanner = ForemanCveScanner::CveReportScanner.new({})
      end
    end

    test 'trivy scan has valid data' do
      data = JSON.parse(File.read(File.join(ForemanCveScanner::Engine.root, 'test/fixtures/trivy.json')))
      raw = {
        'reporter' => 'cve_scan',
        'scan' => data
      }
      ForemanCveScanner::CveReportScanner.add_reporter_data(nil, raw)
      assert_equal raw['logs'].count, 10
      assert_equal raw['logs'][0]['log']['level'], 'info'
      assert_equal raw['logs'][0]['log']['messages']['message'], 'CVE-2020-12762: json-c, libfastjson: integer overflow and out-of-bounds write via a large JSON file # url: https://avd.aquasec.com/nvd/cve-2020-12762'
    end

    test 'grype scan has valid data' do
      data = JSON.parse(File.read(File.join(ForemanCveScanner::Engine.root, 'test/fixtures/grype.json')))
      raw = {
        'reporter' => 'cve_scan',
        'scan' => data
      }
      ForemanCveScanner::CveReportScanner.add_reporter_data(nil, raw)
      assert_equal raw['logs'].count, 18
      assert_equal raw['logs'][0]['log']['level'], 'info'
      assert_equal raw['logs'][0]['log']['messages']['message'], 'CVE-2007-0086: The Apache HTTP Server, when accessed through a TCP connection with a large window size, allows remote attackers to cause a denial of service (network bandwidth consumption) via a Range header that specifies multiple copies of the same fragment. # url: https://nvd.nist.gov/vuln/detail/CVE-2007-0086'
    end
  end
end
