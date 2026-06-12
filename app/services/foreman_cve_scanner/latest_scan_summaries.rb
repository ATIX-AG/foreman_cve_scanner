# frozen_string_literal: true

module ForemanCveScanner
  class LatestScanSummaries
    def initialize(host_scope:, host_ids:)
      @host_scope = host_scope
      @host_ids = host_ids
    end

    def call
      latest_scans.map { |scan| summary_for(scan) }
    end

    private

    attr_reader :host_scope, :host_ids

    def latest_scans
      ids = requested_host_ids
      return [] if ids.empty?

      table = ::ForemanCveScanner::CveScan.table_name
      ::ForemanCveScanner::CveScan.where(host_id: ids)
                                  .select("DISTINCT ON (host_id) #{table}.*")
                                  .order(:host_id, scanned_at: :desc, id: :desc)
    end

    def requested_host_ids
      ids = Array(host_ids).map(&:to_s).map(&:strip).grep(/\A\d+\z/).uniq
      return [] if ids.empty?

      host_scope.where(id: ids).pluck(:id)
    end

    def summary_for(scan)
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
