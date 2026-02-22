# frozen_string_literal: true

module ForemanCveScanner
  # Adds CVE scan associations to hosts.
  module HostExtensions
    extend ActiveSupport::Concern

    included do
      has_many :cve_scans,
        class_name: 'ForemanCveScanner::CveScan',
        foreign_key: :host_id,
        dependent: :destroy,
        inverse_of: :host
    end
  end
end
