# frozen_string_literal: true

module ForemanCveScanner
  # Scans ConfigReports after import for indicators of an CveScanner report and
  # sets the origin of the report to 'CveScanner'
  class CveReportScanner
    def self.add_reporter_data(_report, raw)
      scanner = ForemanCveScanner::CveReportScanner.new(raw)
      scanner.generate
      raw['logs'] = scanner.logs
      raw['status'] = scanner.status
      raw['metrics'] = scanner.metrics
      raw['report_status_calculator_options'] = { :metrics => %w[critical high medium low total] }
    end

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

    def logs
      @logs
    end

    def status
      @status
    end

    def metrics
      res = @status
      res['total'] = @status.values.sum
      return res
    end

    private

    def generate_log_from_unified(id, entry)
      return {
        'log': {
          'level': consume_severity_level(entry['severity']),
          'messages': { 
            message: "#{id}: #{entry['title']} # url: #{entry['url']}"
          },
          sources: {
            source: "#{entry['name']} @ #{entry['version']}"
          }
        }
      }.deep_stringify_keys
    end

    def consume_severity_level(severity)
      @status[severity.downcase] = 0 unless @status.has_key?(severity.downcase)
      @status[severity.downcase] += 1

      log = case severity
            when 'CRITICAL'
              'err'
            when 'HIGH'
              'warning'
            when 'MEDIUM'
              'info'
            when 'LOW'
              'debug'
            else 
              'info'
            end
      return log
    end

    def generate_grype_entry(entry)
      unified = {}
      unified['name'] = entry['artifact']['name']
      unified['version'] = entry['artifact']['version']
      unified['title'] = entry['vulnerability']['description'].gsub(/[\[\]"\\]/, "")
      unified['severity'] = entry['vulnerability']['severity']
      unified['url'] = entry['vulnerability']['dataSource']
      return unified
    end

    def generate_trivy_entry(entry)
      unified = {}
      unified['name'] = entry['PkgName']
      unified['version'] = entry['InstalledVersion']
      unified['title'] = entry['Title'].gsub(/[\[\]"\\]/, "")
      unified['severity'] = entry['Severity']
      unified['url'] = entry['PrimaryURL']  
      unified['status'] = entry['Status'] 
      unified['fixed'] = entry['FixedVersion'] || 'open'
      unified['published'] = entry['PublishedDate'] if entry.has_key?('PublishedDate')
      return unified
    end

    def generate_unified_vuls
      j = @raw_data['scan']

      vuls = {}
      if j.has_key?('matches')  # Grype
        j['matches'].each do |vul|
          vuls[vul['vulnerability']['id']] = generate_grype_entry(vul)
        end
      elsif j.has_key?('Results') # Trivy
        j['Results'].each do |r|
          next unless r.has_key? 'Vulnerabilities'
          r['Vulnerabilities'].each do |vul|
            vuls[vul['VulnerabilityID']] = generate_trivy_entry(vul)
          end
        end   
      else
        Rails.logger.error "Unsupported cve scanner report format"
        raise ::Foreman::Exception.new(_('Invalid report'))
      end

      vuls
    end
  end
end
