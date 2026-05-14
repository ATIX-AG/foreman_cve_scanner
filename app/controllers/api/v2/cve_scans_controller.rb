# frozen_string_literal: true

require 'csv'

module Api
  module V2
    # API controller for CVE scans per host.
    class CveScansController < V2::BaseController
      before_action :find_host

      def resource_class
        ::ForemanCveScanner::CveScan
      end

      api :GET, '/hosts/:host_id/cve_scans', N_('List CVE scans for a host')
      description N_('Returns paginated CVE scan summaries for a host.')
      param :host_id, :identifier, required: true
      param :page, :number, desc: N_('Page number, starting at 1')
      param :per_page, :number, desc: N_('Number of results per page')
      def index
        @cve_scans = cve_scans_index_scope.paginate(paginate_options)
      end

      api :GET, '/hosts/:host_id/cve_scans/latest', N_('Get latest CVE scan for a host')
      description N_('Returns the most recent CVE scan for a host.')
      param :host_id, :identifier, required: true
      def latest
        @cve_scan = cve_scans_index_scope.first
        head :no_content if @cve_scan.nil?
      end

      api :GET, '/hosts/:host_id/cve_scans/:id', N_('Show CVE scan for a host')
      description N_('Returns a specific CVE scan by id for a host.')
      param :host_id, :identifier, required: true
      param :id, :identifier, required: true
      def show
        @cve_scan = resource_class.for_host(@host.id).find(params[:id])
      end

      api :GET, '/hosts/:host_id/cve_scans/compare', N_('Compare two CVE scans for a host')
      description N_('Returns a comparison between two CVE scans for a host.')
      param :host_id, :identifier, required: true
      param :first_id, :identifier, required: true
      param :second_id, :identifier, required: true
      def compare
        return compare_params_missing unless params[:first_id].present? && params[:second_id].present?

        first_scan = resource_class.for_host(@host.id).find_by(id: params[:first_id])
        second_scan = resource_class.for_host(@host.id).find_by(id: params[:second_id])

        render json: ::ForemanCveScanner::ScanComparison.compare(first_scan, second_scan)
      end

      api :DELETE, '/hosts/:host_id/cve_scans/:id', N_('Delete a CVE scan')
      description N_('Deletes a specific CVE scan by id for a host.')
      param :host_id, :identifier, required: true
      param :id, :identifier, required: true
      def destroy
        @cve_scan = resource_class.for_host(@host.id).find(params[:id])
        process_response @cve_scan.destroy
      end

      api :GET, '/hosts/:host_id/cve_scans/:id/export', N_('Export a CVE scan as CSV')
      description N_('Exports the findings of a specific CVE scan as CSV.')
      param :host_id, :identifier, required: true
      param :id, :identifier, required: true
      def export
        @cve_scan = resource_class.for_host(@host.id).find(params[:id])

        send_data(
          findings_csv(@cve_scan),
          filename: export_filename(@cve_scan),
          type: 'text/csv; charset=utf-8',
          disposition: 'attachment'
        )
      end

      private

      CSV_HEADERS = [
        'Severity',
        'Published',
        'Package',
        'Affected version',
        'Fixed version',
        'Status',
        'CVE',
        'Title',
        'URL',
      ].freeze

      def cve_scans_index_scope
        scope = resource_class.for_host(@host.id).recent_first
        return scope unless respond_to?(:resource_scope_for_index, true)
        return scope unless scope.respond_to?(:search_for)

        resource_scope_for_index(scope)
      end

      def find_host
        scope = ::Host::Base.authorized(:view_hosts)
        @host = scope.find_by(name: params[:host_id]) || scope.find_by(id: params[:host_id])
        return if @host.present?

        not_found
      end

      def findings_csv(scan)
        CSV.generate do |csv|
          csv << CSV_HEADERS
          Array(scan.findings).each { |finding| csv << csv_row_for(finding) }
        end
      end

      def export_filename(scan)
        timestamp = scan.created_at&.utc&.strftime('%Y-%m-%d-%H%M%S')
        "#{['cve-report', @host.shortname, scan.id, timestamp].compact.join('-')}.csv"
      end

      def csv_row_for(finding)
        [
          finding['severity'],
          finding['published'],
          finding['name'],
          finding['version'],
          finding['fixed'],
          finding['status'].presence || 'open',
          finding['id'],
          finding['title'],
          finding['url'],
        ]
      end

      def compare_params_missing
        render json: { error: { message: 'first_id and second_id are required' } },
               status: :unprocessable_entity
      end
    end
  end
end
