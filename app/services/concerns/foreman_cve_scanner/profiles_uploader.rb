# frozen_string_literal: true

module ForemanCveScanner
  module ProfilesUploader
    def upload
      result = super
      return result unless result && Setting[:run_cve_scan_after_host_profiles_upload]

      begin
        composer = ::JobInvocationComposer.for_feature(
          :run_cve_scan,
          @host,
          scanner: Setting[:preferred_cve_scanner]
        )
        composer.trigger!
      rescue StandardError => e
        Rails.logger.error(
          "Failed to schedule CVE scan after host profiles upload: #{e.class}: #{e.message}"
        )
      end

      result
    end
  end
end
