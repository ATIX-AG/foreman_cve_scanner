# frozen_string_literal: true

module HostStatus
  # Host status entry reflecting latest CVE scan severities.
  class CveStatus < Status
    CVE_SCANNER_STATUS_NONE = 0
    CVE_SCANNER_STATUS_LOW = 1
    CVE_SCANNER_STATUS_MEDIUM = 2
    CVE_SCANNER_STATUS_CRITICAL_HIGH = 3

    def self.status_name
      N_('CVE')
    end

    def to_label(_options = {})
      case latest_scan_severity
      when :critical_high
        N_('Critical or high CVEs')
      when :medium
        N_('Medium CVEs')
      when :low
        N_('Low CVEs')
      when :none
        N_('No CVE scans')
      else
        N_('No CVEs')
      end
    end

    def to_global(_options = {})
      case latest_scan_severity
      when :critical_high
        HostStatus::Global::ERROR
      when :medium, :none
        HostStatus::Global::WARN
      else
        HostStatus::Global::OK
      end
    end

    def to_status(_options = {})
      case latest_scan_severity
      when :critical_high
        CVE_SCANNER_STATUS_CRITICAL_HIGH
      when :medium
        CVE_SCANNER_STATUS_MEDIUM
      when :low
        CVE_SCANNER_STATUS_LOW
      else
        CVE_SCANNER_STATUS_NONE
      end
    end

    private

    def latest_scan
      @latest_scan ||= ::ForemanCveScanner::CveScan.for_host(host_id).recent_first.first
    end

    def latest_scan_severity
      scan = latest_scan
      return :none if scan.nil?

      return :critical_high if scan.critical.to_i.positive? || scan.high.to_i.positive?
      return :medium if scan.medium.to_i.positive?
      return :low if scan.low.to_i.positive?

      :none
    end
  end
end
