# frozen_string_literal: true

module ForemanCveScanner
  # Stores a single CVE scan result for a host.
  class CveScan < ApplicationRecord
    self.table_name = 'foreman_cve_scanner_cve_scans'

    belongs_to :host, class_name: '::Host::Managed'

    validates :host_id, :scanner, :source, :scanned_at, :raw, :summary, :findings, presence: true

    scope :for_host, ->(host_id) { where(host_id: host_id) }
    scope :recent_first, -> { order(scanned_at: :desc, id: :desc) }

    def self.worst_severity(metrics)
      %w[critical high medium low].find { |severity| metrics[severity].to_i.positive? } || 'none'
    end
  end
end
