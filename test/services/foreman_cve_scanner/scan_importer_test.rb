# frozen_string_literal: true

require 'test_plugin_helper'

module ForemanCveScanner
  class ScanImporterTest < ActiveSupport::TestCase
    def setup
      @host = FactoryBot.create(:host)
    end

    test 'import_for_host! persists scan from trivy output' do
      output = wrap_output(load_fixture('trivy.json'))
      importer = ForemanCveScanner::ScanImporter.new(output)

      count_before = ForemanCveScanner::CveScan.count
      scan = importer.import_for_host!(@host)

      assert_equal count_before + 1, ForemanCveScanner::CveScan.count
      assert_not_nil scan
      assert_equal @host.id, scan.host_id
      assert_equal 'trivy', scan.scanner
    end

    test 'import_for_host! sets totals and findings for trivy output' do
      output = wrap_output(load_fixture('trivy.json'))
      importer = ForemanCveScanner::ScanImporter.new(output)

      scan = importer.import_for_host!(@host)

      assert_operator scan.total, :>, 0
      assert_equal scan.total, scan.findings.count
    end

    test 'import_for_host! persists scan from proxy output' do
      output = load_fixture('grype.json')
      proxy_output = {
        'proxy_output' => {
          'result' => [
            { 'output_type' => 'stdout', 'output' => "===START\n" },
            { 'output_type' => 'stdout', 'output' => output },
            { 'output_type' => 'stdout', 'output' => "\n===END\n" },
          ],
        },
      }
      importer = ForemanCveScanner::ScanImporter.new(proxy_output)

      scan = importer.import_for_host!(@host)

      assert_not_nil scan
      assert_equal 'grype', scan.scanner
      assert_operator scan.total, :>, 0
    end

    test 'import_for_host! returns nil when no json markers' do
      importer = ForemanCveScanner::ScanImporter.new('no markers here')

      scan = importer.import_for_host!(@host)

      assert_nil scan
    end

    test 'import_for_host! returns nil when json is invalid' do
      importer = ForemanCveScanner::ScanImporter.new("===START\n{bad\n===END")

      scan = importer.import_for_host!(@host)

      assert_nil scan
    end

    private

    def load_fixture(name)
      path = File.join(ForemanCveScanner::Engine.root, 'test/fixtures', name)
      JSON.parse(File.read(path)).to_json
    end

    def wrap_output(json_text)
      [
        '===START',
        json_text,
        '===END',
      ].join("\n")
    end
  end
end
