require File.expand_path('lib/foreman_cve_scanner/version', __dir__)

Gem::Specification.new do |s|
  s.name        = 'foreman_cve_scanner'
  s.version     = ForemanCveScanner::VERSION
  s.metadata    = { 'is_foreman_plugin' => 'true' }
  s.license     = 'GPL-3.0'
  s.authors     = ['Bernhard Suttner']
  s.email       = ['suttner@atix.de']
  s.homepage    = 'https://atix.de'
  s.summary     = 'Run CVE scan on host and collect report'
  # also update locale/gemspec.rb
  s.description     = 'Run CVE scan on host and collect report'

  s.files = Dir['{app,config,db,lib,locale,webpack}/**/*'] + ['LICENSE', 'Rakefile', 'README.md']
  s.test_files = Dir['test/**/*'] + Dir['webpack/**/__tests__/*.js']

  s.required_ruby_version = '>= 2.7'

  s.add_development_dependency 'rdoc'
  s.add_development_dependency 'rubocop'
  s.add_development_dependency 'rubocop-minitest'
  s.add_development_dependency 'rubocop-performance'
  s.add_development_dependency 'rubocop-rails'
end
