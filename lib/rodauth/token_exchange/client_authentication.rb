# frozen_string_literal: true

require "base64"
require "uri"

module Rodauth
  module TokenExchange
    module ClientAuthentication
      BASIC_SCHEME = /\A *Basic(?:\s|\z)/i.freeze

      private

      def require_oauth_application
        authorization = request.env["HTTP_AUTHORIZATION"]
        basic = authorization && BASIC_SCHEME.match?(authorization)
        methods = [basic, !param_or_nil("client_secret").to_s.empty?, !param_or_nil("client_assertion").to_s.empty?]
        if methods.count { |present| present } > 1
          redirect_response_error("invalid_request")
        end
        return super unless basic

        token = authorization[/\A *Basic +([^\s]+)\z/i, 1]
        authorization_required unless token

        # Preserve the authentication checks supplied by other OAuth features.
        begin
          request.env["HTTP_AUTHORIZATION"] = "Basic #{token}"
          super
        ensure
          request.env["HTTP_AUTHORIZATION"] = authorization
        end
      end

      def supports_auth_method?(application, auth_method)
        return super unless @oauth_token_exchange_params && auth_method == "none"
        return false unless application

        # PKCE/device grant exceptions must not make an exchange client public.
        configured = application[oauth_applications_token_endpoint_auth_method_column]
        methods = configured ? configured.split(/ +/) : oauth_default_token_endpoint_auth_methods
        methods.include?("none")
      end

      def require_oauth_application_from_client_secret_basic(token)
        begin
          credentials = Base64.strict_decode64(token).split(":", 2)
          authorization_required unless credentials.length == 2
          client_id, client_secret = credentials.map { |value| URI.decode_www_form_component(value) }
          authorization_required unless client_id.valid_encoding? && client_secret.valid_encoding?
        rescue ArgumentError
          authorization_required
        end
        application = db[oauth_applications_table].where(oauth_applications_client_id_column => client_id).first
        authorization_required unless supports_auth_method?(application, "client_secret_basic") &&
                                      secret_matches?(application, client_secret)
        application
      end
    end
  end
end
