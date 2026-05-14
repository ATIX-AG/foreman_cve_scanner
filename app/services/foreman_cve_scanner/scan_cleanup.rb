# frozen_string_literal: true

module ForemanCveScanner
  class ScanCleanup
    SETTING_NAME = :cve_scan_delete_after_days

    def initialize(scope: ::ForemanCveScanner::CveScan.all, days: nil)
      @scope = scope
      @days = days
    end

    def cleanup!
      return 0 unless retention_days.positive?

      deleted = @scope.where('scanned_at < ?', retention_cutoff).delete_all
      Rails.logger.info("Deleted #{deleted} CVE scans older than #{retention_days} days") if deleted.positive?
      deleted
    end

    private

    def retention_days
      @retention_days ||= configured_days.to_i
    end

    def configured_days
      @days.nil? ? Setting[SETTING_NAME] : @days
    end

    def retention_cutoff
      retention_days.days.ago
    end
  end
end
