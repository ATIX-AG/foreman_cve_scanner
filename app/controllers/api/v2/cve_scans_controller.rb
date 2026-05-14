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

      api :POST, '/hosts/:host_id/cve_scans/import', N_('Import CVE scan for a host')
      description N_('Imports a CVE scan for a host from normalized findings data.')
      param :host_id, :identifier, required: true
      param :cve_scan, Hash, required: true do
        param :scanner, String, required: true
        param :source, String, required: true
        param :scanned_at, String, required: true
        param :findings, Array, required: true, desc: N_('Array of CVE finding objects.') do
          param :id, String, required: true, desc: N_('CVE identifier')
          param :name, String, required: true, desc: N_('Affected package name')
          param :severity, String, required: true, desc: N_('Severity, for example CRITICAL, HIGH, MEDIUM or LOW')
          param :version, String, required: false, desc: N_('Affected or installed version')
          param :fixed, String, required: false, desc: N_('Fixed version or open')
          param :status, String, required: false, desc: N_('Scanner-specific status such as affected or fixed')
          param :title, String, required: false, desc: N_('Human-readable finding title')
          param :published, String, required: false, desc: N_('Published timestamp')
          param :url, String, required: false, desc: N_('Reference URL')
        end
      end
      def import
        @cve_scan = resource_class.new(build_import_attributes)

        if @cve_scan.save
          render 'api/v2/cve_scans/show', status: :created
        else
          render(
            json: { error: { message: @cve_scan.errors.full_messages.to_sentence } },
            status: :unprocessable_entity
          )
        end
      end

      api :GET, '/hosts/:host_id/cve_scans/compare', N_('Compare two CVE scans for a host')
      description N_('Returns a comparison between two CVE scans for a host.')
      param :host_id, :identifier, required: true
      param :first_id, :identifier, required: true
      param :second_id, :identifier, required: true
      def compare
        return compare_params_missing unless params[:first_id].present? && params[:second_id].present?

        first_scan = find_scan_for_host(params[:first_id])
        return unless first_scan

        second_scan = find_scan_for_host(params[:second_id])
        return unless second_scan

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
        scope = ::Host::Base.authorized(host_permission)
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
        timestamp = scan.scanned_at&.utc&.strftime('%Y-%m-%d-%H%M%S')
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
        render(
          json: { error: { message: 'first_id and second_id are required' } },
          status: :unprocessable_entity
        )
      end

      def scan_not_found(id)
        render(
          json: { error: { message: "CVE scan with id '#{id}' not found for this host" } },
          status: :not_found
        )
      end

      def find_scan_for_host(scan_id)
        scan = resource_class.for_host(@host.id).find_by(id: scan_id)
        scan_not_found(scan_id) unless scan
        scan
      end

      def build_import_attributes
        payload = import_params.to_h
        findings = Array(payload['findings']).map(&:to_h)
        metrics = findings_metrics(findings)

        {
          host: @host,
          scanner: payload['scanner'],
          source: payload['source'],
          scanned_at: payload['scanned_at'],
          raw: payload,
          summary: metrics.merge('worst' => ::ForemanCveScanner::CveScan.worst_severity(metrics)),
          findings: findings,
          total: metrics['total'],
          critical: metrics['critical'],
          high: metrics['high'],
          medium: metrics['medium'],
          low: metrics['low'],
        }
      end

      def import_params
        params.require(:cve_scan).permit(
          :scanner,
          :source,
          :scanned_at,
          findings: %i[id name severity version fixed status title published url]
        )
      end

      def findings_metrics(findings)
        severities = findings.map { |finding| finding['severity'].to_s.upcase }
        {
          'total' => findings.size,
          'critical' => severities.count('CRITICAL'),
          'high' => severities.count('HIGH'),
          'medium' => severities.count('MEDIUM'),
          'low' => severities.count('LOW'),
        }
      end

      def host_permission
        return :import_cve_scans if action_name == 'import'
        return :destroy_cve_scans if action_name == 'destroy'

        :view_cve_scans
      end
    end
  end
end
