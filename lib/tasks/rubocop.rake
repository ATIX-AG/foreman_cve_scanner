# frozen_string_literal: true

begin
  require 'rubocop/rake_task'

  test_patterns = [
    "#{ForemanCveScanner::Engine.root}/*.gemspec",
    "#{ForemanCveScanner::Engine.root}/*.rb",
    "#{ForemanCveScanner::Engine.root}/app/**/*.rb",
    "#{ForemanCveScanner::Engine.root}/config/**/*.rb",
    "#{ForemanCveScanner::Engine.root}/db/**/*.rb",
    "#{ForemanCveScanner::Engine.root}/lib/**/*.rake",
    "#{ForemanCveScanner::Engine.root}/lib/**/*.rb",
    "#{ForemanCveScanner::Engine.root}/test/**/*.rb",
  ]

  namespace :foreman_cve_scanner do
    desc 'Runs Rubocop style checker'
    RuboCop::RakeTask.new(:rubocop) do |task|
      task.patterns = test_patterns
    end

    desc 'Runs Rubocop style checker with xml output for Jenkins'
    RuboCop::RakeTask.new('rubocop:jenkins') do |task|
      task.patterns = test_patterns
      task.requires = ['rubocop/formatter/checkstyle_formatter']
      task.formatters = ['RuboCop::Formatter::CheckstyleFormatter']
      task.options = ['--no-color', '--out', 'rubocop.xml']
    end
  end
rescue LoadError
  # 'Rubocop not loaded.'
end
