# frozen_string_literal: true

class AddSourceAndScannedAtToForemanCveScannerCveScans < ActiveRecord::Migration[6.1]
  def up
    add_column :foreman_cve_scanner_cve_scans, :source, :string
    add_column :foreman_cve_scanner_cve_scans, :scanned_at, :datetime

    execute <<~SQL.squish
      UPDATE foreman_cve_scanner_cve_scans
      SET source = 'rex', scanned_at = created_at
      WHERE source IS NULL OR scanned_at IS NULL
    SQL

    change_column_null :foreman_cve_scanner_cve_scans, :source, false
    change_column_null :foreman_cve_scanner_cve_scans, :scanned_at, false

    add_index :foreman_cve_scanner_cve_scans, %i[host_id scanned_at],
      order: { scanned_at: :desc }
  end

  def down
    remove_index :foreman_cve_scanner_cve_scans, %i[host_id scanned_at]
    remove_column :foreman_cve_scanner_cve_scans, :scanned_at
    remove_column :foreman_cve_scanner_cve_scans, :source
  end
end
