# frozen_string_literal: true

module ForemanCveScanner
  class KatelloFixAvailability
    STATUS_INSTALLABLE = 'installable'
    STATUS_APPLICABLE = 'applicable'
    STATUS_UNAVAILABLE = 'unavailable'
    STATUS_UNKNOWN = 'unknown'

    CONFIDENCE_PACKAGE_MATCH = 'package_match'
    CONFIDENCE_CVE_ONLY = 'cve_only'

    UNKNOWN_MISSING_CVE = 'missing_cve'
    UNKNOWN_QUERY_FAILED = 'query_failed'

    def initialize(host, findings)
      @host = host
      @findings = Array(findings)
    end

    def call
      return findings_without_enrichment unless katello_available? && enabled?

      decorate_with_katello
    rescue StandardError => e
      Rails.logger.error(
        "Katello CVE fix lookup failed for host_id=#{@host&.id}: #{e.class}: #{e.message}"
      )
      decorate_all_unknown(UNKNOWN_QUERY_FAILED)
    end

    private

    def decorate_with_katello
      cve_ids = @findings.filter_map { |finding| cve_id_for(finding) }.uniq
      return decorate_all_unknown(UNKNOWN_MISSING_CVE) if cve_ids.empty?

      installable_by_cve = errata_by_cve(installable_errata(cve_ids))
      applicable_by_cve = errata_by_cve(applicable_errata(cve_ids))

      @findings.map do |finding|
        cve_id = cve_id_for(finding)
        next decorate_finding(finding, unknown_fix(UNKNOWN_MISSING_CVE)) if cve_id.blank?

        fix = fix_for(finding, installable_by_cve[cve_id], applicable_by_cve[cve_id])
        decorate_finding(finding, fix)
      end
    end

    def fix_for(finding, installable_errata, applicable_errata)
      return matched_fix(STATUS_INSTALLABLE, finding, installable_errata) if installable_errata.present?
      return matched_fix(STATUS_APPLICABLE, finding, applicable_errata) if applicable_errata.present?

      {
        'status' => STATUS_UNAVAILABLE,
        'reason' => nil,
        'confidence' => nil,
        'errata' => [],
      }
    end

    def matched_fix(status, finding, errata)
      matched_errata = errata_matching_package(errata, package_name_for(finding))
      selected_errata = matched_errata.presence || errata

      {
        'status' => status,
        'reason' => nil,
        'confidence' => confidence_for(matched_errata),
        'errata' => selected_errata.map { |erratum| erratum_payload(erratum) },
      }
    end

    def confidence_for(matched_errata)
      matched_errata.present? ? CONFIDENCE_PACKAGE_MATCH : CONFIDENCE_CVE_ONLY
    end

    def decorate_all_unknown(reason)
      @findings.map { |finding| decorate_finding(finding, unknown_fix(reason)) }
    end

    def findings_without_enrichment
      @findings.map { |finding| finding.to_h.deep_dup }
    end

    def decorate_finding(finding, fix)
      finding.to_h.deep_dup.merge('katello_fix' => fix)
    end

    def unknown_fix(reason)
      {
        'status' => STATUS_UNKNOWN,
        'reason' => reason,
        'confidence' => nil,
        'errata' => [],
      }
    end

    def installable_errata(cve_ids)
      errata_matching_cves(host_installable_errata, cve_ids)
    end

    def applicable_errata(cve_ids)
      errata_matching_cves(host_applicable_errata, cve_ids)
    end

    def host_installable_errata
      return ::Katello::Erratum.none unless host_content_facet

      host_content_facet.installable_errata.security
    end

    def host_applicable_errata
      return ::Katello::Erratum.none unless host_content_facet

      host_content_facet.applicable_errata.security
    end

    def host_content_facet
      return nil unless @host.respond_to?(:content_facet)

      @host.content_facet
    end

    def errata_matching_cves(scope, cve_ids)
      scope = scope.includes(:cves, :packages, :deb_packages)
      cve_filtered_errata(scope, cve_ids).distinct
    end

    def cve_filtered_errata(scope, cve_ids)
      return cve_join_filtered_errata(scope, cve_ids) unless scope.respond_to?(:search_for)

      scope.search_for(cve_search_query(cve_ids))
    rescue StandardError => e
      Rails.logger.debug do
        "Katello CVE scoped search failed for host_id=#{@host&.id}: #{e.class}: #{e.message}"
      end
      cve_join_filtered_errata(scope, cve_ids)
    end

    def cve_join_filtered_errata(scope, cve_ids)
      scope
        .joins(:cves)
        .where(::Katello::ErratumCve.table_name => { cve_id: cve_ids })
    end

    def cve_search_query(cve_ids)
      cve_ids.map { |cve_id| %(cve = "#{escape_search_value(cve_id)}") }.join(' OR ')
    end

    def escape_search_value(value)
      value.to_s.gsub(/[\\"]/) { |char| "\\#{char}" }
    end

    def errata_by_cve(errata)
      grouped = Hash.new { |hash, key| hash[key] = [] }
      errata.each do |erratum|
        erratum.cves.each { |cve| grouped[cve.cve_id] << erratum }
      end
      grouped
    end

    def errata_matching_package(errata, package_name)
      return [] if package_name.blank?

      normalized_package_name = normalize_package_name(package_name)
      errata.select do |erratum|
        erratum_package_names(erratum).any? do |name|
          normalize_package_name(name) == normalized_package_name
        end
      end
    end

    def erratum_payload(erratum)
      {
        'id' => erratum.id,
        'errata_id' => erratum.errata_id,
        'title' => erratum.title,
        'severity' => erratum.severity,
        'packages' => erratum_package_names(erratum),
      }
    end

    def erratum_package_names(erratum)
      (erratum.packages.map(&:name) + erratum.deb_packages.map(&:name)).compact.uniq
    end

    def cve_id_for(finding)
      finding.to_h['id'].presence
    end

    def package_name_for(finding)
      finding.to_h['name'].presence
    end

    def normalize_package_name(name)
      name.to_s.downcase.strip
    end

    def katello_available?
      Foreman::Plugin.installed?(:katello)
    end

    def enabled?
      Setting[:enable_katello_cve_fix_availability]
    end
  end
end
