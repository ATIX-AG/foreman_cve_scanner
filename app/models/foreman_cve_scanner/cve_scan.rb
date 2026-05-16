# frozen_string_literal: true

module ForemanCveScanner
  # Stores a single CVE scan result for a host.
  class CveScan < ApplicationRecord
    self.table_name = 'foreman_cve_scanner_cve_scans'

    SEVERITY_LEVELS = %w[critical high medium low].freeze

    belongs_to :host, class_name: '::Host::Managed'

    validates :host_id, :scanner, :source, :scanned_at, :raw, :summary, presence: true
    validate :findings_must_be_present

    scope :for_host, ->(host_id) { where(host_id: host_id) }
    scope :recent_first, -> { order(scanned_at: :desc, id: :desc) }

    def self.worst_severity(metrics)
      SEVERITY_LEVELS.find { |severity| metrics[severity].to_i.positive? } || 'none'
    end

    private

    def findings_must_be_present
      errors.add(:findings, :blank) if findings.nil?
    end
  end
end
