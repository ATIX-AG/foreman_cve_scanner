# frozen_string_literal: true

module ForemanCveScanner
  # Import CVE scan results from REX job output and persist them.
  class ScanImporter
    def initialize(job_output)
      @job_output = job_output
    end

    def import_for_host!(host)
      scan_json = format_output(@job_output)
      return nil if scan_json.nil?

      scanner_name = ::ForemanCveScanner::CveReportScanner.detect_scanner(scan_json)
      persist_scan!(host, scanner_name, scan_json)
    end

    private

    def format_output(job_output)
      output_source = normalize_job_output(job_output)
      json_text = extract_json(output_source)
      if json_text.blank? && output_source.to_s.strip.present?
        Rails.logger.warn('CVE scan output did not contain markers or JSON content')
      end
      return nil if json_text.blank?

      JSON.parse(json_text)
    rescue JSON::ParserError => e
      Rails.logger.error("CVE scan output parse failed: #{e}")
      nil
    end

    def extract_json(output_source)
      output = output_source.to_s.each_line(chomp: true)
                            .drop_while { |line| !line.start_with?('===START') }
                            .drop(1)
                            .take_while { |line| !line.start_with?('===END') }
                            .reject(&:empty?)
                            .join
      output.strip
    end

    def normalize_job_output(job_output)
      return concat_proxy_output(job_output) if job_output.is_a?(Hash) && job_output.key?('proxy_output')

      output_source = job_output
      output_source = job_output.humanize if job_output.respond_to?(:humanize) && !job_output.is_a?(String)
      output_source.to_s
    end

    def concat_proxy_output(job_output)
      result = job_output.dig('proxy_output', 'result') || []
      result.filter_map { |item| item['output'] if item['output_type'] == 'stdout' }.join
    end

    def persist_scan!(host, scanner_name, scan_json)
      scanner = ::ForemanCveScanner::CveReportScanner.new('scan' => scan_json)
      scanner.generate

      metrics = scanner.metrics
      scan = ::ForemanCveScanner::CveScan.create!(
        build_scan_attributes(host, scanner_name, scan_json, metrics, scanner)
      )
      refresh_host_status(host)
      scan
    end

    def refresh_host_status(host)
      status = ::HostStatus::CveStatus.find_or_initialize_by(host: host)
      status.refresh!
    rescue StandardError => e
      Rails.logger.error("CVE status refresh failed for host_id=#{host.id}: #{e}")
    end

    def build_scan_attributes(host, scanner_name, scan_json, metrics, scanner)
      summary = metrics.merge('worst' => ::ForemanCveScanner::CveScan.worst_severity(metrics))
      {
        host: host,
        scanner: scanner_name,
        source: 'rex',
        scanned_at: Time.current,
        raw: scan_json,
        summary: summary,
        findings: build_findings(scanner),
        total: metrics['total'].to_i,
        critical: metrics['critical'].to_i,
        high: metrics['high'].to_i,
        medium: metrics['medium'].to_i,
        low: metrics['low'].to_i,
      }
    end

    def build_findings(scanner)
      scanner.unified_vulnerabilities.map do |id, entry|
        entry.merge('id' => id)
      end
    end
  end
end
