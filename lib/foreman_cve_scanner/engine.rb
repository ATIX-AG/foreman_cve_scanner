# frozen_string_literal: true

require 'foreman_remote_execution'

module ForemanCveScanner
  # Rails engine for the Foreman CVE Scanner plugin.
  class Engine < ::Rails::Engine
    engine_name 'foreman_cve_scanner'

    initializer 'foreman_cve_scanner.load_app_instance_data' do |app|
      ForemanCveScanner::Engine.paths['db/migrate'].existent.each do |path|
        app.config.paths['db/migrate'] << path
      end
    end

    initializer 'foreman_cve_scanner.register_plugin', before: :finisher_hook do |app|
      app.reloader.to_prepare do
        ForemanCveScanner::Engine.register_plugin
      end
    end

    # Include concerns in this config.to_prepare block
    config.to_prepare do
      require_dependency 'foreman_cve_scanner/host_extensions'
      Host::Managed.include ForemanCveScanner::HostExtensions
      require_dependency 'host_status/cve_status'
      HostStatus.status_registry.add(HostStatus::CveStatus)
      ForemanCveScanner::Engine.register_rex_features
    end

    rake_tasks do
      Rake::Task['db:seed'].enhance do
        ForemanCveScanner::Engine.load_seed
      end
    end

    def self.register_rex_features
      RemoteExecutionFeature.register(
        :run_cve_scan,
        N_('Run a CVE scan on a host'),
        description: N_('Run CVE scan on host'),
        host_action_button: true
      )
    end

    def self.register_plugin
      Foreman::Plugin.register :foreman_cve_scanner do
        requires_foreman '>= 3.13'
        register_global_js_file 'fills'
        apipie_documented_controllers ForemanCveScanner::Engine.documented_controllers
        ForemanCveScanner::Engine.register_cleanup_setting(self)
        ForemanCveScanner::Engine.register_permissions(self)
        add_all_permissions_to_default_roles
      end
    end

    def self.documented_controllers
      ["#{ForemanCveScanner::Engine.root}/app/controllers/api/v2/*.rb"]
    end

    def self.register_cleanup_setting(plugin)
      plugin.settings do
        category :foreman_cve_scanner, N_('CVE Scanner') do
          setting 'cve_scan_delete_after_days',
            type: :integer,
            default: 90,
            full_name: N_('Delete CVE scans after X days'),
            description: = N_(
              'Delete CVE scans older than the configured number of days. ' \
              'Set to 0 to disable automatic cleanup.'
            )
        end
      end
    end

    def self.register_permissions(plugin)
      plugin.security_block :foreman_cve_scanner do
        permission :view_cve_scans,
          { 'api/v2/cve_scans': %i[index latest show export compare] },
          resource_type: 'Host'
        permission :import_cve_scans,
          { 'api/v2/cve_scans': %i[import] },
          resource_type: 'Host'
        permission :destroy_cve_scans,
          { 'api/v2/cve_scans': %i[destroy] },
          resource_type: 'Host'
      end
    end
  end
end
