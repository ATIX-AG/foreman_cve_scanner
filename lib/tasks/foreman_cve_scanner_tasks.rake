# frozen_string_literal: true

# Tests
namespace :test do
  desc 'Foreman Cve Scanner plugin tests'
  Rake::TestTask.new(:foreman_cve_scanner) do |t|
    test_dir = File.join(__dir__, '..', '..', 'test')
    t.libs << ['test', test_dir]
    t.pattern = "#{test_dir}/**/*_test.rb"
    t.test_files = [Rails.root.join('test/unit/foreman/access_permissions_test.rb')]
    t.verbose = false
    t.warning = false
  end
end

Rake::Task[:test].enhance ['test:foreman_cve_scanner']

namespace :foreman_cve_scanner do
  desc 'Delete old CVE scans using the configured retention or a DAYS override'
  task cleanup_scans: :environment do
    override = ENV['DAYS']
    deleted = ForemanCveScanner::ScanCleanup.new(days: override.presence).cleanup!
    basis = override.present? ? "DAYS=#{override}" : 'the configured retention'

    puts "Deleted #{deleted} CVE scans using #{basis}."
  end
end
