# frozen_string_literal: true

require 'test_plugin_helper'

module Api
  module V2
    class CveScansControllerTest < ActionController::TestCase
      def setup
        @host = FactoryBot.create(:host)
        @scan_old = create_scan(created_at: 2.hours.ago, scanned_at: 2.hours.ago, total: 1, low: 1)
        @scan_new = create_scan(created_at: 1.hour.ago, scanned_at: 1.hour.ago, total: 2, high: 2)
      end

      test 'index returns scans for host' do
        get :index, params: { host_id: @host.id }
        assert_response :success
        body = ActiveSupport::JSON.decode(@response.body)
        assert_not_nil body['results']
        assert_equal 2, body['results'].size
      end

      test 'latest returns most recent scan' do
        get :latest, params: { host_id: @host.id }
        assert_response :success
        body = ActiveSupport::JSON.decode(@response.body)
        assert_equal @scan_new.id, body['id']
      end

      test 'show returns scan by id' do
        get :show, params: { host_id: @host.id, id: @scan_old.id }
        assert_response :success
        body = ActiveSupport::JSON.decode(@response.body)
        assert_equal @scan_old.id, body['id']
      end

      test 'import imports external scan for host' do
        assert_difference('ForemanCveScanner::CveScan.count', 1) do
          post :import, params: {
            host_id: @host.id,
            cve_scan: create_payload,
          }
        end

        assert_response :created
        body = ActiveSupport::JSON.decode(@response.body)
        assert_equal 'external', body['source']
        assert_equal 1, body['critical']
      end

      test 'import rejects scan without scanned_at' do
        post :import, params: {
          host_id: @host.id,
          cve_scan: create_payload.except(:scanned_at),
        }

        assert_response :unprocessable_entity
      end

      test 'compare returns scan comparison for host' do
        set_comparison_findings!

        get :compare, params: {
          host_id: @host.id,
          first_id: @scan_old.id,
          second_id: @scan_new.id,
        }

        assert_response :success
        body = ActiveSupport::JSON.decode(@response.body)
        assert_equal @scan_old.id, body['previous']['id']
        assert_equal 1, body['summary']['updated']
        assert_equal 1, body['summary']['resolved']
        assert_equal 1, body['summary']['new']
      end

      test 'compare includes diff payload for updated finding' do
        set_comparison_findings!

        get :compare, params: {
          host_id: @host.id,
          first_id: @scan_old.id,
          second_id: @scan_new.id,
        }

        assert_response :success
        body = ActiveSupport::JSON.decode(@response.body)
        updated_row = body['results'].find { |row| row['id'] == 'CVE-1' }
        assert_equal 'updated', updated_row['status']
        assert_equal 'CRITICAL', updated_row['diff']['severity']['new']
      end

      test 'compare requires both scan ids' do
        get :compare, params: { host_id: @host.id, first_id: @scan_old.id }

        assert_response :unprocessable_entity
      end

      test 'export returns csv headers for scan by id' do
        set_export_findings!

        get :export, params: { host_id: @host.id, id: @scan_old.id }

        assert_response :success
        assert_export_headers
      end

      test 'export returns csv body for scan by id' do
        set_export_findings!

        get :export, params: { host_id: @host.id, id: @scan_old.id }

        assert_response :success
        assert_export_body
      end

      test 'show does not return a scan from another host' do
        other_host = FactoryBot.create(:host)
        other_scan = create_scan(host: other_host, total: 1, low: 1)

        assert_not_found do
          get :show, params: { host_id: @host.id, id: other_scan.id }
        end
      end

      test 'export does not return a scan from another host' do
        other_host = FactoryBot.create(:host)
        other_scan = create_scan(host: other_host, total: 1, low: 1)

        assert_not_found do
          get :export, params: { host_id: @host.id, id: other_scan.id }
        end
      end

      test 'compare does not return scans from another host' do
        other_host = FactoryBot.create(:host)
        other_scan = create_scan(host: other_host, total: 1, low: 1)

        assert_not_found do
          get :compare, params: {
            host_id: @host.id,
            first_id: @scan_old.id,
            second_id: other_scan.id,
          }
        end
      end

      test 'index returns not found for unknown host' do
        get :index, params: { host_id: 'does-not-exist' }
        assert_response :not_found
      end

      test 'index finds host by name' do
        get :index, params: { host_id: @host.name }
        assert_response :success
        body = ActiveSupport::JSON.decode(@response.body)
        assert_not_nil body['results']
        assert_equal 2, body['results'].size
      end

      test 'latest returns no content when no scans exist' do
        ForemanCveScanner::CveScan.delete_all

        get :latest, params: { host_id: @host.id }
        assert_response :no_content
      end

      test 'destroy deletes scan for host' do
        assert_difference('ForemanCveScanner::CveScan.count', -1) do
          delete :destroy, params: { host_id: @host.id, id: @scan_old.id }
        end

        assert_response :success
      end

      test 'destroy does not delete a scan from another host' do
        other_host = FactoryBot.create(:host)
        other_scan = create_scan(host: other_host, total: 1, low: 1)

        assert_no_difference('ForemanCveScanner::CveScan.count') do
          assert_not_found do
            delete :destroy, params: { host_id: @host.id, id: other_scan.id }
          end
        end
      end

      private

      def create_scan(options = {})
        defaults = {
          created_at: Time.now.utc,
          scanned_at: Time.current,
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          host: @host,
        }
        options = defaults.merge(options)
        ForemanCveScanner::CveScan.create!(
          host: options[:host],
          scanner: 'trivy',
          source: 'rex',
          scanned_at: options[:scanned_at],
          created_at: options[:created_at],
          raw: { 'dummy' => true },
          summary: { 'worst' => 'low' },
          findings: [{ 'id' => 'CVE-0000-0000' }],
          total: options[:total],
          critical: options[:critical],
          high: options[:high],
          medium: options[:medium],
          low: options[:low]
        )
      end

      def set_export_findings!
        @scan_old.update!(
          findings: [
            {
              'severity' => 'HIGH',
              'published' => '2026-02-20',
              'name' => 'openssl',
              'version' => '1.1',
              'fixed' => '1.2',
              'status' => 'fixed',
              'id' => 'CVE-2026-0001',
              'title' => 'OpenSSL issue',
              'url' => 'https://example.test/CVE-2026-0001',
            },
          ]
        )
      end

      def create_payload
        {
          scanner: 'custom-scanner',
          source: 'external',
          scanned_at: '2026-05-14T08:00:00Z',
          findings: [external_finding],
        }
      end

      def set_comparison_findings!
        @scan_old.update!(findings: old_comparison_findings)
        @scan_new.update!(findings: new_comparison_findings)
      end

      def external_finding
        {
          id: 'CVE-2026-1111',
          name: 'openssl',
          severity: 'CRITICAL',
          version: '1.0',
          fixed: '1.1',
          status: 'affected',
          title: 'OpenSSL issue',
          published: '2026-05-14T06:00:00Z',
          url: 'https://example.test/CVE-2026-1111',
        }
      end

      def old_comparison_findings
        [
          comparison_finding(
            id: 'CVE-1',
            name: 'openssl',
            severity: 'HIGH',
            version: '1.0',
            title: 'OpenSSL issue'
          ),
          comparison_finding(
            id: 'CVE-2',
            name: 'curl',
            severity: 'LOW',
            version: '1.0',
            title: 'Curl issue'
          ),
        ]
      end

      def new_comparison_findings
        [
          comparison_finding(
            id: 'CVE-1',
            name: 'openssl',
            severity: 'CRITICAL',
            version: '1.0',
            title: 'OpenSSL issue'
          ),
          comparison_finding(
            id: 'CVE-3',
            name: 'bash',
            severity: 'MEDIUM',
            version: '2.0',
            title: 'Bash issue',
            published: '2026-02-21'
          ),
        ]
      end

      def comparison_finding(attributes)
        {
          'id' => attributes.fetch(:id),
          'name' => attributes.fetch(:name),
          'severity' => attributes.fetch(:severity),
          'version' => attributes.fetch(:version),
          'title' => attributes.fetch(:title),
          'published' => attributes.fetch(:published, '2026-02-20'),
        }
      end

      def assert_not_found
        yield
        assert_response :not_found
      rescue ActiveRecord::RecordNotFound
        assert true
      end

      def assert_export_headers
        assert_includes @response.header['Content-Type'], 'text/csv'
        assert_includes @response.header['Content-Disposition'], 'attachment'
        assert_includes @response.header['Content-Disposition'], @host.shortname
      end

      def assert_export_body
        assert_includes @response.body, 'Severity,Published,Package'
        assert_includes @response.body, 'CVE-2026-0001'
        assert_includes @response.body, 'openssl'
      end
    end
  end
end
