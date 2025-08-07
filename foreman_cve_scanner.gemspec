require File.expand_path('lib/foreman_cve_scanner/version', __dir__)
require 'date'

# rubocop:disable Rails/Date
Gem::Specification.new do |s|
  s.name        = 'foreman_cve_scanner'
  s.version     = ForemanCveScanner::VERSION
  s.date        = Date.today.to_s
  s.metadata    = { 'is_foreman_plugin' => 'true' }
  s.license     = 'GPL-3.0'
  s.authors     = ['Bernhard Suttner']
  s.email       = ['suttner@atix.de']
  s.homepage    = 'https://github.com/ATIX-AG/foreman_cve_scanner'
  s.summary     = 'Run CVE scan on host and collect report'
  # also update locale/gemspec.rb
  s.description = 'Run CVE scan on host and collect report'

  s.files = Dir['{app,config,db,lib,locale,webpack}/**/*'] + ['LICENSE', 'Rakefile', 'README.md']
  s.test_files = Dir['test/**/*'] + Dir['webpack/**/__tests__/*.js']

  s.required_ruby_version = '>= 2.7', '< 4'

  s.add_dependency 'foreman_remote_execution', '>= 9.0', '< 17'

  s.add_development_dependency 'rake'
  s.add_development_dependency 'rdoc'
end
# rubocop:enable Rails/Date
