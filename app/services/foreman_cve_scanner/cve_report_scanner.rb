# frozen_string_literal: true

module ForemanCveScanner
  # Parses raw CVE scanner reports and produces unified logs/metrics.
  # rubocop:disable Metrics/ClassLength
  class CveReportScanner
    SEVERITY_ORDER = %w[CRITICAL HIGH MEDIUM LOW UNKNOWN].freeze

    def self.identify_origin(raw)
      'CveScanner' if cve_scanner_report?(raw)
    end

    def self.cve_scanner_report?(raw)
      raw['reporter'] == 'cve_scan'
    end

    def initialize(raw)
      @raw_data = raw
      @cve_report_data = generate_unified_vuls
    end

    def generate
      @status = {}
      @logs = []
      @cve_report_data.each do |id, cve|
        @logs << generate_log_from_unified(id, cve)
      end
      @logs
    end

    attr_reader :logs, :status

    def unified_vulnerabilities
      @cve_report_data
    end

    def self.detect_scanner(scan_json)
      return 'grype' if scan_json.is_a?(Hash) && scan_json.key?('matches')
      return 'trivy' if scan_json.is_a?(Hash) && scan_json.key?('Results')

      'unknown'
    end

    def metrics
      known = %w[critical high medium low]
      res = @status.slice(*known)
      res['total'] = res.values.sum
      res
    end

    private

    def generate_log_from_unified(id, entry)
      {
        log: {
          level: consume_severity_level(entry['severity']),
          messages: {
            message: "#{id}: #{entry['title']} # url: #{entry['url']}",
          },
          sources: {
            source: "#{entry['name']} @ #{entry['version']}",
          },
        },
      }.deep_stringify_keys
    end

    def consume_severity_level(severity)
      severity = severity.to_s.strip.upcase
      @status[severity.downcase] = 0 unless @status.key?(severity.downcase)
      @status[severity.downcase] += 1

      {
        'CRITICAL' => 'err',
        'HIGH' => 'warning',
        'MEDIUM' => 'info',
        'LOW' => 'debug',
      }.fetch(severity, 'info')
    end

    def generate_grype_entry(entry)
      {
        'name' => entry['artifact']['name'],
        'version' => entry['artifact']['version'],
        'title' => entry['vulnerability']['description'].to_s.gsub(/[\[\]"\\]/, ''),
        'severity' => entry['vulnerability']['severity'],
        'url' => entry['vulnerability']['dataSource'],
      }
    end

    def generate_trivy_entry(entry)
      unified = {
        'name' => entry['PkgName'],
        'version' => entry['InstalledVersion'],
        'title' => entry['Title'].to_s.gsub(/[\[\]"\\]/, ''),
        'severity' => entry['Severity'],
        'url' => entry['PrimaryURL'],
        'status' => entry['Status'],
        'fixed' => entry['FixedVersion'] || 'open',
      }
      unified['published'] = entry['PublishedDate'] if entry.key?('PublishedDate')
      unified
    end

    # rubocop:disable Metrics/AbcSize, Metrics/MethodLength, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
    def generate_unified_vuls
      raise ::Foreman::Exception, _('Invalid CVE scanner report') unless @raw_data.key?('scan')

      j = @raw_data['scan']
      vuls = {}
      if j.key?('matches') # Grype
        j['matches'].each do |vul|
          vuls[vul['vulnerability']['id']] = generate_grype_entry(vul)
        end
      elsif j.key?('Results') # Trivy
        j['Results'].each do |r|
          next unless r.key? 'Vulnerabilities'

          r['Vulnerabilities'].each do |vul|
            vuls[vul['VulnerabilityID']] = generate_trivy_entry(vul)
          end
        end
      else
        Rails.logger.error 'Unsupported cve scanner report format'
        raise ::Foreman::Exception, _('Unsupported cve scanner report format')
      end

      vuls
    end
    # rubocop:enable Metrics/AbcSize, Metrics/MethodLength, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
  end
  # rubocop:enable Metrics/ClassLength
end
