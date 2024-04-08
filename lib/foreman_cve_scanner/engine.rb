require 'foreman_remote_execution'

module ForemanCveScanner
  class Engine < ::Rails::Engine
    engine_name 'foreman_cve_scanner'

    config.autoload_paths += Dir["#{config.root}/app/services"]
    config.autoload_paths += Dir["#{config.root}/app/lib"]

    initializer 'foreman_cve_scanner.register_plugin', :before => :finisher_hook do |_app|
      Foreman::Plugin.register :foreman_cve_scanner do
        requires_foreman '>= 3.5.0'
        register_report_scanner ForemanCveScanner::CveReportScanner
        register_report_origin 'CveScanner', 'ConfigReport'
      end
    end

    # Include concerns in this config.to_prepare block
    config.to_prepare do
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
  end
end
