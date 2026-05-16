# frozen_string_literal: true

require 'test_plugin_helper'

module ForemanCveScanner
  class ProfilesUploaderTest < ActiveSupport::TestCase
    class DummyUploader
      prepend ForemanCveScanner::ProfilesUploader

      def initialize(host:, result:)
        @host = host
        @result = result
      end

      def upload
        @result
      end
    end

    def setup
      skip 'Katello is not installed' unless Foreman::Plugin.installed?(:katello)

      @host = FactoryBot.create(:host)
      @previous_preferred_scanner = Setting[:preferred_cve_scanner]
      @previous_run_after_upload = Setting[:run_cve_scan_after_host_profiles_upload]
    end

    def teardown
      return unless Foreman::Plugin.installed?(:katello)

      Setting[:preferred_cve_scanner] = @previous_preferred_scanner
      Setting[:run_cve_scan_after_host_profiles_upload] = @previous_run_after_upload
    end

    test 'upload schedules cve scan when setting is enabled' do
      Setting[:preferred_cve_scanner] = 'grype'
      Setting[:run_cve_scan_after_host_profiles_upload] = true

      captured = {}
      triggering = Struct.new(:mode).new
      composer = Struct.new(:triggering) do
        attr_reader :triggered

        def trigger!
          @triggered = true
        end
      end.new(triggering)

      JobInvocationComposer.stub(:for_feature, lambda { |feature, host, scanner:|
        captured[:feature] = feature
        captured[:host] = host
        captured[:scanner] = scanner
        composer
      }) do
        assert DummyUploader.new(host: @host, result: true).upload
      end

      assert_equal [:run_cve_scan, @host, 'grype'],
        [captured[:feature], captured[:host], captured[:scanner]]
      assert_equal :future, triggering.mode
      assert composer.triggered
    end

    test 'upload keeps upstream result when scan scheduling fails' do
      Setting[:run_cve_scan_after_host_profiles_upload] = true

      JobInvocationComposer.stub(:for_feature, lambda { |_feature, _host, scanner:|
        raise StandardError, scanner
      }) do
        assert DummyUploader.new(host: @host, result: true).upload
      end
    end

    test 'upload does not schedule cve scan when setting is disabled' do
      Setting[:run_cve_scan_after_host_profiles_upload] = false

      JobInvocationComposer.stub(:for_feature, lambda { |_feature, _host, scanner:|
        flunk("unexpected scanner #{scanner}")
      }) do
        assert DummyUploader.new(host: @host, result: true).upload
      end
    end
  end
end
