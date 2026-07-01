# frozen_string_literal: true

module ForemanCveScanner
  class ScanPostProcessor
    def initialize(host)
      @host = host
    end

    def call
      refresh_host_status
      cleanup_old_scans
    end

    private

    attr_reader :host

    def refresh_host_status
      status = ::HostStatus::CveStatus.find_or_initialize_by(host: host)
      status.refresh!
    rescue StandardError => e
      Rails.logger.error("CVE status refresh failed for host_id=#{host.id}: #{e}")
    end

    def cleanup_old_scans
      ::ForemanCveScanner::ScanCleanup.new(scope: host.cve_scans).cleanup!
    end
  end
end
