# frozen_string_literal: true

module ForemanCveScanner
  class ScanComparison
    DIFF_FIELDS = %w[severity version fixed status title published url].freeze

    def self.compare(first_scan, second_scan)
      new(first_scan, second_scan).compare
    end

    def initialize(first_scan, second_scan)
      @first_scan = first_scan
      @second_scan = second_scan
    end

    def compare
      rows = comparison_rows

      {
        previous: scan_payload(@first_scan),
        current: scan_payload(@second_scan),
        summary: summarize(rows),
        results: rows,
      }
    end

    private

    def comparison_rows
      identities.map do |identity|
        previous_finding = previous_map[identity]
        current_finding = current_map[identity]
        current_values = current_finding || previous_finding
        diff = diff_for(previous_finding, current_finding)

        {
          key: identity,
          status: comparison_status_for(previous_finding, current_finding, diff),
          id: value_for(current_values, 'id'),
          name: value_for(current_values, 'name'),
          title: value_for(current_values, 'title'),
          published: value_for(current_values, 'published'),
          severity: value_for(current_values, 'severity'),
          version: value_for(current_values, 'version'),
          fixed: value_for(current_values, 'fixed'),
          scan_status: normalized_value_for(current_values, 'status'),
          url: value_for(current_values, 'url'),
          diff: diff,
        }
      end
    end

    def summarize(rows)
      rows.each_with_object(default_summary) do |row, summary|
        summary[row[:status]] += 1
      end
    end

    def default_summary
      {
        'new' => 0,
        'resolved' => 0,
        'updated' => 0,
        'unchanged' => 0,
      }
    end

    def comparison_status_for(previous_finding, current_finding, diff)
      return 'new' if previous_finding.nil?
      return 'resolved' if current_finding.nil?
      return 'updated' if diff.any?

      'unchanged'
    end

    def diff_for(previous_finding, current_finding)
      return {} if previous_finding.nil? || current_finding.nil?

      DIFF_FIELDS.each_with_object({}) do |field, diff|
        old_value = normalized_value_for(previous_finding, field)
        new_value = normalized_value_for(current_finding, field)
        next if old_value == new_value

        diff[response_field_name(field)] = {
          old: old_value,
          new: new_value,
        }
      end
    end

    def previous_map
      @previous_map ||= findings_map(@first_scan)
    end

    def current_map
      @current_map ||= findings_map(@second_scan)
    end

    def identities
      @identities ||= (previous_map.keys + current_map.keys).uniq
    end

    def findings_map(scan)
      Array(scan.findings).index_by { |finding| finding_identity(finding) }
    end

    def finding_identity(finding)
      "#{finding['id']}::#{finding['name']}"
    end

    def normalize_status(status)
      status.presence || 'open'
    end

    def value_for(finding, field)
      finding&.[](field).to_s
    end

    def normalized_value_for(finding, field)
      return normalize_status(finding&.[]('status')) if field == 'status'

      value_for(finding, field)
    end

    def response_field_name(field)
      field == 'status' ? 'scan_status' : field
    end

    def scan_payload(scan)
      {
        id: scan.id,
        host_id: scan.host_id,
        scanner: scan.scanner,
        source: scan.source,
        scanned_at: scan.scanned_at,
        total: scan.total,
        critical: scan.critical,
        high: scan.high,
        medium: scan.medium,
        low: scan.low,
        summary: scan.summary,
      }
    end
  end
end
