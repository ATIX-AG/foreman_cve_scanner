# frozen_string_literal: true

module Actions
  module ForemanCveScanner
    # Dynflow action that parses a CVE scan job output and stores the results.
    class CveScannerJob < Actions::EntryAction
      def self.subscribe
        Actions::RemoteExecution::RunHostJob
      end

      def plan(job_invocation, host, *_args)
        return unless correct_feature?(job_invocation, 'run_cve_scan')

        plan_self(host_id: host.id, job_invocation_id: job_invocation.id)
      end

      def finalize(*_args)
        host = Host.find(input[:host_id])

        ::ForemanCveScanner::ScanImporter.new(task.main_action.continuous_output)
                                         .import_for_host!(host)
      end

      private

      def correct_feature?(job_invocation, feature)
        RemoteExecutionFeature.where(job_template_id: job_invocation.pattern_template_invocations
                                                                    .first
                                                                    .template_id, label: feature).any?
      end
    end
  end
end
