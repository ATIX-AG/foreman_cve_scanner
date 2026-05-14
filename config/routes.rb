# frozen_string_literal: true

Rails.application.routes.draw do
  namespace :api, defaults: { format: 'json' } do
    scope '(:apiv)', module: :v2,
                     defaults: { apiv: 'v2' },
                     apiv: /v1|v2/,
                     constraints: ApiConstraints.new(version: 2, default: true) do
      constraints(host_id: %r{[^/]+}) do
        resources :hosts, only: [] do
          resources :cve_scans, only: %i[index show destroy] do
            collection do
              post :import
              get :latest
              get :compare
            end
            member do
              get :export
            end
          end
        end
      end
    end
  end
end
