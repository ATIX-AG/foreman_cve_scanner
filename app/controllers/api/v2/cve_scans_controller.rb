# frozen_string_literal: true

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

      api :DELETE, '/hosts/:host_id/cve_scans/:id', N_('Delete a CVE scan')
      description N_('Deletes a specific CVE scan by id for a host.')
      param :host_id, :identifier, required: true
      param :id, :identifier, required: true
      def destroy
        @cve_scan = resource_class.for_host(@host.id).find(params[:id])
        process_response @cve_scan.destroy
      end

      private

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
    end
  end
end
