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

      test 'index returns not found for unknown host' do
        get :index, params: { host_id: 'does-not-exist' }
        assert_response :not_found
      end

      test 'latest returns no content when no scans exist' do
        ForemanCveScanner::CveScan.delete_all

        get :latest, params: { host_id: @host.id }
        assert_response :no_content
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
        }
        options = defaults.merge(options)
        ForemanCveScanner::CveScan.create!(
          host: @host,
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
    end
  end
end
