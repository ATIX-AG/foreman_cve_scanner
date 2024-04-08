require 'test_plugin_helper'

module ForemanCveScanner
  class CveReportScannerTest < ActiveSupport::TestCase
    def setup
      raw = {
        'reporter' => 'cve_scan'
      }
      @scanner = ForemanCveScanner::CveReportScanner.new(raw)
    end

    test 'should identify as cve scan' do
      assert_equasl @scanner.identify_origin, 'CveScanner'
    end
  end
end
