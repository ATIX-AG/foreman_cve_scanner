# frozen_string_literal: true

require 'test_plugin_helper'

module ForemanCveScanner
  class TemplateHelpersTest < ActiveSupport::TestCase
    include ForemanCveScanner::TemplateHelpers

    def setup
      @previous_preferred_scanner = Setting[:preferred_cve_scanner]
    end

    def teardown
      Setting[:preferred_cve_scanner] = @previous_preferred_scanner
    end

    test 'foreman_cve_scanner returns preferred scanner setting' do
      Setting[:preferred_cve_scanner] = 'grype'

      assert_equal 'grype', foreman_cve_scanner('preferred_scanner')
    end

    test 'foreman_cve_scanner raises for unknown setting name' do
      assert_raises(::Foreman::Exception) do
        foreman_cve_scanner('unknown_setting')
      end
    end
  end
end
