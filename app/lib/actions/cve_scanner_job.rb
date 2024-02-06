# frozen_string_literal: true

module Actions
  module ForemanCveScanner
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
        if host.present?
          cve_scan_report = format_output(task.main_action.continuous_output.humanize)
          report = Hash.new
          report["host"] = host.name
          report["logs"] = []
          report["scan"] = cve_scan_report
          report["reported_at"] = Time.now.utc.to_s
          report['reporter'] = 'cve_scan'
          ConfigReportImporter::import(report)
	end
      end

      private

      def correct_feature?(job_invocation, feature)
        RemoteExecutionFeature.where(job_template_id: job_invocation.pattern_template_invocations
                                                                    .first
                                                                    .template_id, label: feature).any?
      end

      def format_output(job_output)
        output = job_output.each_line(chomp: true)
                           .drop_while { |l| !l.start_with? '===START' }.drop(1)
                           .take_while { |l| !l.start_with? '===END' }
                           .reject(&:empty?)
                           .join('')
        JSON.parse(output)
      end
    end
  end
end

