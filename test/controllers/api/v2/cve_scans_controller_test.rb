# frozen_string_literal: true

require 'test_plugin_helper'

module Api
  module V2
    class CveScansControllerTest < ActionController::TestCase
      def setup
        @host = FactoryBot.create(:host)
        @scan_old = create_scan(created_at: 2.hours.ago, total: 1, low: 1)
        @scan_new = create_scan(created_at: 1.hour.ago, total: 2, high: 2)
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

      # rubocop:disable Metrics/MethodLength
      def create_scan(options = {})
        defaults = {
          created_at: Time.now.utc,
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
      # rubocop:enable Metrics/MethodLength

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
