# frozen_string_literal: true

require 'test_plugin_helper'

module ForemanCveScanner
  class ScanImporterTest < ActiveSupport::TestCase
    def setup
      @host = FactoryBot.create(:host)
      @previous_retention = Setting[:cve_scan_delete_after_days]
    end

    def teardown
      Setting[:cve_scan_delete_after_days] = @previous_retention
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
      assert_equal 'rex', scan.source
    end

    test 'import_for_host! sets totals and findings for trivy output' do
      output = wrap_output(load_fixture('trivy.json'))
      importer = ForemanCveScanner::ScanImporter.new(output)

      scan = importer.import_for_host!(@host)

      assert_operator scan.total, :>, 0
      assert_equal scan.total, scan.findings.count
      assert_not_nil scan.scanned_at
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

    test 'import_for_host! raises when no json markers' do
      importer = ForemanCveScanner::ScanImporter.new('no markers here')

      assert_raises(::Foreman::Exception) do
        importer.import_for_host!(@host)
      end
    end

    test 'import_for_host! raises when json is invalid' do
      importer = ForemanCveScanner::ScanImporter.new("===START\n{bad\n===END")

      assert_raises(::Foreman::Exception) do
        importer.import_for_host!(@host)
      end
    end

    test 'import_for_host! raises when marker block is empty' do
      importer = ForemanCveScanner::ScanImporter.new("===START\n===END")

      assert_raises(::Foreman::Exception) do
        importer.import_for_host!(@host)
      end
    end

    test 'import_for_host! cleans up old scans for the host using retention setting' do
      Setting[:cve_scan_delete_after_days] = 1
      old_scan = ForemanCveScanner::CveScan.create!(
        host: @host,
        scanner: 'trivy',
        source: 'rex',
        scanned_at: 3.days.ago,
        raw: { 'dummy' => true },
        summary: { 'worst' => 'low' },
        findings: [{ 'id' => 'CVE-0000-0000' }],
        total: 1,
        critical: 0,
        high: 0,
        medium: 0,
        low: 1
      )
      output = wrap_output(load_fixture('trivy.json'))
      importer = ForemanCveScanner::ScanImporter.new(output)

      scan = importer.import_for_host!(@host)

      assert_not_nil scan
      assert_not ForemanCveScanner::CveScan.exists?(old_scan.id)
      assert ForemanCveScanner::CveScan.exists?(scan.id)
    end

    test 'import_for_host! persists scan with zero findings' do
      output = wrap_output(
        {
          'Results' => [
            {
              'Target' => '/',
              'Class' => 'os-pkgs',
            },
          ],
        }.to_json
      )
      importer = ForemanCveScanner::ScanImporter.new(output)

      scan = importer.import_for_host!(@host)

      assert_not_nil scan
      assert_equal 'trivy', scan.scanner
      assert_empty scan.findings
      assert_equal 0, scan.total
      assert_equal 'none', scan.summary['worst']
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
