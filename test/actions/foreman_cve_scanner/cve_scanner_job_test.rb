# frozen_string_literal: true

require 'test_plugin_helper'

module ForemanCveScanner
  class CveScannerJobTest < ActiveSupport::TestCase
    def setup
      @host = FactoryBot.create(:host)
    end

    test 'format_output parses json between markers across proxy output entries' do
      job_output = {
        'proxy_output' => {
          'result' => [
            { 'output_type' => 'stdout', 'output' => "===START\n{\"key\":" },
            { 'output_type' => 'stdout', 'output' => "1}\n===END\n" },
          ],
        },
      }

      importer = ForemanCveScanner::ScanImporter.new(job_output)
      parsed = importer.send(:format_output, job_output)

      assert_equal({ 'key' => 1 }, parsed)
    end

    test 'persist_scan! stores scan and metrics' do
      scan_json = JSON.parse(
        File.read(File.join(ForemanCveScanner::Engine.root, 'test/fixtures/trivy.json'))
      )

      importer = ForemanCveScanner::ScanImporter.new('')
      scan = importer.send(:persist_scan!, @host, 'trivy', scan_json)

      assert scan.persisted?
      assert scan.total.positive?
      assert_equal @host.id, scan.host_id
    end

    test 'import_for_host! creates scan from rex output' do
      output = [
        '===START',
        File.read(File.join(ForemanCveScanner::Engine.root, 'test/fixtures/trivy.json')),
        '===END',
      ].join("\n")

      importer = ForemanCveScanner::ScanImporter.new(output)
      scan = importer.import_for_host!(@host)

      assert scan.persisted?
      assert_equal @host.id, scan.host_id
    end
  end
end
