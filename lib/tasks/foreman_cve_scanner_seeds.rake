# frozen_string_literal: true

namespace :foreman_cve_scanner do
  desc 'Seed Foreman CVE Scanner job templates'
  task seed_job_templates: :environment do
    require Rails.root.join('lib/seed_helper')
    require 'foreman_remote_execution'
    paths = Dir["#{ForemanCveScanner::Engine.root}/app/views/foreman_cve_scanner/job_templates/*.erb"]
    SeedHelper.import_templates(paths, 'ForemanCveScanner')
    puts "Seeded #{paths.size} Foreman CVE Scanner job templates"
  end
end
