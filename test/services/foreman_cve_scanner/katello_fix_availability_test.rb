# frozen_string_literal: true

require 'test_plugin_helper'

module ForemanCveScanner
  class KatelloFixAvailabilityTest < ActiveSupport::TestCase
    Erratum = Struct.new(
      :id,
      :errata_id,
      :title,
      :severity,
      :cves,
      :packages,
      :deb_packages
    )
    Cve = Struct.new(:cve_id)
    Package = Struct.new(:name)
    ContentFacet = Struct.new(:installable_errata, :applicable_errata)

    class ErrataRelation
      include Enumerable

      attr_reader :search_queries

      def initialize(errata)
        @errata = errata
        @search_queries = []
      end

      def each(&block)
        @errata.each(&block)
      end

      def security
        self
      end

      def includes(*)
        self
      end

      def search_for(query)
        @search_queries << query
        self
      end

      def distinct
        @errata.uniq
      end
    end

    def setup
      @host = FactoryBot.create(:host)
      @findings = [
        {
          'id' => 'CVE-2026-0001',
          'name' => 'openssl',
          'severity' => 'HIGH',
        },
      ]
    end

    test 'does not add katello enrichment when katello is not installed' do
      service = KatelloFixAvailability.new(@host, @findings)
      Foreman::Plugin.stubs(:installed?).with(:katello).returns(false)
      service.expects(:enabled?).never

      enriched_findings = service.call

      assert_equal @findings, enriched_findings
      assert_not enriched_findings.first.key?('katello_fix')
    end

    test 'does not add katello enrichment when disabled' do
      service = KatelloFixAvailability.new(@host, @findings)
      service.stubs(:enabled?).returns(false)
      service.expects(:installable_errata).never

      enriched_findings = service.call

      assert_equal @findings, enriched_findings
      assert_not enriched_findings.first.key?('katello_fix')
    end

    test 'adds unknown enrichment when katello lookup fails' do
      service = KatelloFixAvailability.new(@host, @findings)
      service.stubs(:enabled?).returns(true)
      service.stubs(:katello_available?).returns(true)
      service.stubs(:installable_errata).raises(NameError)

      enriched_findings = service.call
      fix = enriched_findings.first['katello_fix']

      assert_equal 'unknown', fix['status']
      assert_equal 'query_failed', fix['reason']
    end

    test 'marks matching installable errata as installable' do
      service = KatelloFixAvailability.new(@host, @findings)
      erratum = erratum_for('CVE-2026-0001', 'openssl')
      service.stubs(:enabled?).returns(true)
      service.stubs(:katello_available?).returns(true)
      service.stubs(:installable_errata).returns([erratum])
      service.stubs(:applicable_errata).returns([])

      enriched_findings = service.call
      fix = enriched_findings.first['katello_fix']

      assert_equal 'installable', fix['status']
      assert_equal 'package_match', fix['confidence']
      assert_equal(
        ['RHSA-2026:0001'],
        fix['errata'].map { |item| item['errata_id'] }
      )
    end

    test 'marks matching applicable errata as applicable when not installable' do
      service = KatelloFixAvailability.new(@host, @findings)
      erratum = erratum_for('CVE-2026-0001', 'openssl')
      service.stubs(:enabled?).returns(true)
      service.stubs(:katello_available?).returns(true)
      service.stubs(:installable_errata).returns([])
      service.stubs(:applicable_errata).returns([erratum])

      enriched_findings = service.call
      fix = enriched_findings.first['katello_fix']

      assert_equal 'applicable', fix['status']
      assert_equal 'package_match', fix['confidence']
    end

    test 'looks up errata through host content facet cve search' do
      installable_erratum = erratum_for('CVE-2026-0001', 'openssl')
      installable_relation = ErrataRelation.new([installable_erratum])
      applicable_relation = ErrataRelation.new([])
      content_facet = ContentFacet.new(installable_relation, applicable_relation)

      @host.stubs(:content_facet).returns(content_facet)
      service = KatelloFixAvailability.new(@host, @findings)
      service.stubs(:enabled?).returns(true)
      service.stubs(:katello_available?).returns(true)

      enriched_findings = service.call

      assert_equal ['cve = "CVE-2026-0001"'], installable_relation.search_queries
      assert_equal ['cve = "CVE-2026-0001"'], applicable_relation.search_queries
      assert_equal 'installable', enriched_findings.first['katello_fix']['status']
    end

    private

    def erratum_for(cve_id, package_name)
      Erratum.new(
        1,
        'RHSA-2026:0001',
        'Security update',
        'Important',
        [Cve.new(cve_id)],
        [Package.new(package_name)],
        []
      )
    end
  end
end
