# frozen_string_literal: true

module ForemanCveScanner
  # Adds CVE scan associations and search predicates to hosts.
  module HostExtensions
    extend ActiveSupport::Concern

    CVE_SEARCH_COUNT_COLUMNS = %w[total critical high medium low].freeze
    CVE_SEARCH_TEXT_OPERATORS = ['= ', '!= ', '~ ', '!~ '].freeze
    CVE_SEARCH_COMPARE_OPERATORS = ['= ', '!= ', '< ', '> ', '<= ', '>= '].freeze
    CVE_SEARCH_TEXT_SQL_OPERATORS = ['=', '!=', '<>', 'LIKE', 'NOT LIKE', '~', '!~'].freeze
    CVE_SEARCH_COMPARE_SQL_OPERATORS = ['=', '!=', '<>', '<', '>', '<=', '>='].freeze
    # Scoped Search autocompletion expects symbol keys here; boolean keys raise during typing.
    # rubocop:disable Lint/BooleanSymbol
    CVE_SEARCH_BOOLEAN_VALUES = { true: true, false: false }.freeze
    # rubocop:enable Lint/BooleanSymbol
    CVE_SEARCH_SCANNER_VALUES = { trivy: 'trivy', grype: 'grype' }.freeze
    CVE_SEARCH_SOURCE_VALUES = { rex: 'rex', external: 'external' }.freeze

    included do
      has_many :cve_scans,
        class_name: 'ForemanCveScanner::CveScan',
        foreign_key: :host_id,
        dependent: :destroy,
        inverse_of: :host

      scoped_search on: :id, rename: :cve_scanned, only_explicit: true,
        complete_value: CVE_SEARCH_BOOLEAN_VALUES,
        operators: ['= ', '!= '], ext_method: :search_by_cve_scanned

      CVE_SEARCH_COUNT_COLUMNS.each do |column|
        scoped_search on: :id, rename: "cve_#{column}", only_explicit: true,
          complete_enabled: false, validator: ScopedSearch::Validators::INTEGER,
          operators: CVE_SEARCH_COMPARE_OPERATORS, ext_method: :"search_by_cve_#{column}"
      end

      scoped_search on: :id, rename: :cve_scanner, only_explicit: true,
        complete_value: CVE_SEARCH_SCANNER_VALUES, operators: CVE_SEARCH_TEXT_OPERATORS,
        ext_method: :search_by_cve_scanner
      scoped_search on: :id, rename: :cve_source, only_explicit: true,
        complete_value: CVE_SEARCH_SOURCE_VALUES, operators: CVE_SEARCH_TEXT_OPERATORS,
        ext_method: :search_by_cve_source
      scoped_search on: :id, rename: :cve_scanned_at, only_explicit: true,
        complete_enabled: false, operators: CVE_SEARCH_COMPARE_OPERATORS,
        ext_method: :search_by_cve_scanned_at
    end

    module ClassMethods
      def search_by_cve_scanned(_key, operator, value)
        scanned = ::Foreman::Cast.to_bool(value)
        return no_cve_scan_search_results if scanned.nil?

        positive = searched_by_equal_operator?(operator) ? scanned : !scanned
        cve_scan_host_conditions(latest_cve_scans, positive: positive)
      end

      def search_by_cve_total(_key, operator, value)
        search_by_cve_count('total', operator, value)
      end

      def search_by_cve_critical(_key, operator, value)
        search_by_cve_count('critical', operator, value)
      end

      def search_by_cve_high(_key, operator, value)
        search_by_cve_count('high', operator, value)
      end

      def search_by_cve_medium(_key, operator, value)
        search_by_cve_count('medium', operator, value)
      end

      def search_by_cve_low(_key, operator, value)
        search_by_cve_count('low', operator, value)
      end

      def search_by_cve_scanner(_key, operator, value)
        search_by_cve_text('scanner', operator, value)
      end

      def search_by_cve_source(_key, operator, value)
        search_by_cve_text('source', operator, value)
      end

      def search_by_cve_scanned_at(_key, operator, value)
        search_by_cve_column('scanned_at', operator, value)
      end

      private

      def search_by_cve_count(column, operator, value)
        search_by_cve_column(column, sql_operator(operator, CVE_SEARCH_COMPARE_SQL_OPERATORS), value.to_i)
      end

      def search_by_cve_text(column, operator, value)
        operator = sql_operator(operator, CVE_SEARCH_TEXT_SQL_OPERATORS)
        search_by_cve_column(column, operator, value_to_sql(operator, value))
      end

      def search_by_cve_column(column, operator, value)
        scan_table = ::ForemanCveScanner::CveScan.table_name
        condition = sanitize_sql_for_conditions(["#{scan_table}.#{column} #{operator} ?", value])
        cve_scan_host_conditions(latest_cve_scans.where(condition))
      end

      def latest_cve_scans
        scan_table = ::ForemanCveScanner::CveScan.table_name
        latest_sql = ::ForemanCveScanner::CveScan
                     .select("DISTINCT ON (#{scan_table}.host_id) #{scan_table}.*")
                     .order("#{scan_table}.host_id, #{scan_table}.scanned_at DESC, #{scan_table}.id DESC")
                     .to_sql

        ::ForemanCveScanner::CveScan.from("(#{latest_sql}) #{scan_table}")
      end

      def cve_scan_host_conditions(scans, positive: true)
        host_operator = positive ? 'IN' : 'NOT IN'
        { conditions: "#{table_name}.id #{host_operator} (#{scans.select(:host_id).to_sql})" }
      end

      def no_cve_scan_search_results
        { conditions: '1=0' }
      end

      def searched_by_equal_operator?(operator)
        operator.to_s.strip == '='
      end

      def sql_operator(operator, allowed_operators)
        operator = operator.to_s.strip.upcase
        return operator if allowed_operators.include?(operator)

        raise ::ScopedSearch::QueryNotSupported, _("Unsupported CVE scan search operator '%s'") % operator
      end
    end
  end
end
