# frozen_string_literal: true

module ForemanCveScanner
  module TemplateHelpers
    extend ApipieDSL::Class

    apipie :class, 'Macros related to Foreman CVE Scanner templates' do
      name 'Foreman CVE Scanner'
      sections only: %w[all jobs]
    end

    apipie :method, 'Returns values from Foreman CVE Scanner plugin settings' do
      desc 'Use this macro in templates to access CVE Scanner settings in safe mode'
      param :setting_name, String, desc: 'Setting name to resolve'
      returns String, desc: 'Value of the requested CVE Scanner setting'
      raises error: 'Foreman::Exception', desc: 'Raised when an unknown setting name is requested'
      example "foreman_cve_scanner('preferred_scanner') #=> 'trivy'"
    end
    def foreman_cve_scanner(setting_name)
      case setting_name.to_s
      when 'preferred_scanner'
        Setting[:preferred_cve_scanner]
      else
        raise ::Foreman::Exception, _('Unknown Foreman CVE Scanner template setting')
      end
    end
  end
end
