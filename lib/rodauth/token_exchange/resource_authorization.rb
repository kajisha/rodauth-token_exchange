# frozen_string_literal: true

require "uri"

module Rodauth
  module TokenExchange
    # Compatibility with rodauth-oauth 1.7's resource indicators. Keep the
    # authentication/scope/sender-binding chain, replacing only its URL checks
    # for auth classes which explicitly enable this extension.
    module ResourceAuthorization
      def require_oauth_authorization(*scopes)
        return super unless features.include?(:oauth_resource_indicators)

        previous = @oauth_token_exchange_checking_authorization
        begin
          @oauth_token_exchange_checking_authorization = true
          super
        ensure
          @oauth_token_exchange_checking_authorization = previous
        end

        token = authorization_token
        resources = token[oauth_grants_resource_column] || token["resource"]
        return unless resources

        resources = resources.split(" ") if resources.is_a?(String)
        authorization_required unless oauth_token_exchange_resource_matches?(resources)
      end

      private

      def authorization_token
        token = super
        return token unless token && @oauth_token_exchange_checking_authorization

        # Suppress the upstream base_url prefix check only while its full
        # authorization chain runs. Do not alter its cached grant or JWT claims.
        # The original resource restriction is checked immediately afterwards,
        # before require_oauth_authorization returns to the protected route.
        token.reject { |key, _| key == oauth_grants_resource_column || key == "resource" }
      end

      def jwt_decode(token, verify_aud: true, **options)
        return super unless features.include?(:oauth_resource_indicators)

        # The upstream resource wrapper honors verify_aud:false, avoiding both
        # its starts_with? typo and its unsafe prefix matcher. Other verification
        # options, including signature, issuer, expiry, headers and jti, survive.
        claims = super(token, verify_aud: false, **options)
        return claims unless verify_aud
        return unless claims && oauth_token_exchange_resource_matches?(claims["aud"])

        claims
      end

      def oauth_token_exchange_resource_matches?(resources)
        return false unless resources.is_a?(Array) && !resources.empty?

        requested = URI.parse(request.url)
        return false unless oauth_token_exchange_http_resource?(requested)

        resources.any? do |resource|
          next false unless resource.is_a?(String)

          begin
            target = URI.parse(resource)
            next false unless oauth_token_exchange_http_resource?(target)
            next false unless [requested.scheme, requested.host.downcase, requested.port] ==
                              [target.scheme, target.host.downcase, target.port]

            path = target.path
            request_path = requested.path
            path_match = path.empty? || path == "/" || request_path == path ||
                         request_path.start_with?(path.end_with?("/") ? path : "#{path}/")
            path_match && (target.query.nil? || target.query == requested.query)
          rescue URI::InvalidURIError
            false
          end
        end
      rescue URI::InvalidURIError
        false
      end

      def oauth_token_exchange_http_resource?(uri)
        return false unless %w[http https].include?(uri.scheme) && uri.host && !uri.userinfo && !uri.fragment

        # Avoid path aliases which a downstream router might normalize outside
        # the allowed subtree. Encoded separators are deliberately fail-closed.
        return false if uri.path.match?(/%(?:2f|5c)/i)

        uri.path.split("/").none? { |segment| %w[. ..].include?(URI::DEFAULT_PARSER.unescape(segment)) }
      end
    end
  end
end
