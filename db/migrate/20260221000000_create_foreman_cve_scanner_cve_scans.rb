# frozen_string_literal: true

# Creates the CVE scans table for per-host scan history.
class CreateForemanCveScannerCveScans < ActiveRecord::Migration[6.1]
  def change
    create_table :foreman_cve_scanner_cve_scans do |t|
      t.references :host, null: false, foreign_key: true
      t.string :scanner, null: false
      t.jsonb :raw, null: false
      t.jsonb :summary, null: false, default: {}
      t.jsonb :findings, null: false, default: []
      t.integer :total, null: false, default: 0
      t.integer :critical, null: false, default: 0
      t.integer :high, null: false, default: 0
      t.integer :medium, null: false, default: 0
      t.integer :low, null: false, default: 0
      t.timestamps
    end

    add_index :foreman_cve_scanner_cve_scans, %i[host_id created_at]
  end
end
