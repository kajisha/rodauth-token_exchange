# frozen_string_literal: true

require "rodauth/oauth"
require "json"
require "uri"
require "rodauth/token_exchange/client_authentication"
require "rodauth/token_exchange/resource_authorization"

module Rodauth
  module TokenExchange
    GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
    ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
    SINGLE_PARAMETERS = %w[grant_type subject_token subject_token_type actor_token actor_token_type requested_token_type scope].freeze
    TARGET_PARAMETERS = %w[resource audience].freeze
    CLIENT_PARAMETERS = %w[client_id client_secret client_assertion client_assertion_type].freeze
    MAX_FORM_BYTES = 4 * 1024 * 1024
    MAX_FORM_PARAMETERS = 4096
    MAX_ACTOR_DEPTH = 16

    # Rodauth configuration methods live on the auth class, above feature
    # modules. Extend the request instance with these constraints so configured
    # lifetime/reuse values cannot bypass the exchange's security bounds.
    module TokenSettings
      def oauth_access_token_expires_in
        [@oauth_token_exchange_expires_at - Time.now.to_i, 0].max
      end

      def oauth_reuse_access_token
        false
      end
    end
  end

  Feature.define(:oauth_token_exchange, :OauthTokenExchange) do
    depends :oauth_base
    include TokenExchange::ClientAuthentication
    include TokenExchange::ResourceAuthorization

    auth_value_method :oauth_grants_token_exchange_context_column, :token_exchange_context
    auth_methods :oauth_token_exchange_resolve_token, :oauth_token_exchange_authorized?,
                 :oauth_token_exchange_targets_allowed?

    def oauth_grant_types_supported
      super | [TokenExchange::GRANT_TYPE]
    end

    def raw_param(key)
      return @oauth_token_exchange_params[key] if @oauth_token_exchange_params

      super
    end

    def resource_indicators
      return @oauth_token_exchange_params["resource"] if @oauth_token_exchange_params

      super
    end

    # A resolver returns a validated identity, never unverified decoded claims.
    def oauth_token_exchange_resolve_token(token, token_type)
      return unless token_type == TokenExchange::ACCESS_TOKEN_TYPE

      grant = oauth_token_exchange_stored_grant(token)
      return unless grant
      binding_columns = [:certificate_thumbprint, :dpop_jkt]
      binding_columns << oauth_grants_certificate_thumbprint_column if respond_to?(:oauth_grants_certificate_thumbprint_column)
      binding_columns << oauth_grants_dpop_jkt_column if respond_to?(:oauth_grants_dpop_jkt_column)
      return if binding_columns.any? { |binding| grant[binding] }

      context = oauth_token_exchange_context(grant)
      account = grant[oauth_grants_account_id_column]
      return if account && oauth_account_ds(account).empty?

      application = grant[oauth_grants_oauth_application_id_column]
      subject = context["sub"] || account&.to_s ||
                db[oauth_applications_table].where(oauth_applications_id_column => application)
                                           .get(oauth_applications_client_id_column)
      {
        subject: subject, account_id: account, application_id: application,
        scopes: grant[oauth_grants_scopes_column].to_s.split(oauth_scope_separator),
        expires_at: grant[oauth_grants_expires_in_column].to_time.to_i,
        act: context["act"], act_account_ids: context["act_account_ids"], may_act: context["may_act"],
        resources: context.fetch("resource") {
          resource_column = respond_to?(:oauth_grants_resource_column) ? oauth_grants_resource_column : :resource
          grant[resource_column].to_s.split(" ")
        },
        audiences: context.fetch("audience", [])
      }.compact
    end

    def oauth_token_exchange_authorized?(subject, actor)
      return false unless subject[:application_id] == oauth_application[oauth_applications_id_column]

      !actor || oauth_token_exchange_may_act?(subject, actor)
    end

    # RFC 8693 §4.4: every claim in the subject's may_act must identify the actor.
    # Unsupported may_act claims never match, so they deny rather than widen.
    def oauth_token_exchange_may_act?(subject, actor)
      may_act = oauth_token_exchange_may_act(subject)
      return false unless may_act

      # A sub is unique only within its issuer, so the issuer always takes part.
      claims = {"sub" => actor[:subject], "iss" => actor[:issuer]}
      may_act.all? { |claim, value| claims.key?(claim) && claims[claim] == value }
    end

    # A may_act without iss names a principal of the subject's issuer.
    def oauth_token_exchange_may_act(subject)
      may_act = subject[:may_act]
      return unless may_act.is_a?(Hash) && !may_act.empty?

      may_act = may_act.transform_keys(&:to_s)
      may_act["iss"] = subject[:issuer] unless may_act.key?("iss")
      may_act
    end

    def oauth_token_exchange_targets_allowed?(resources, audiences, _subject, _actor)
      resources.empty? && audiences.empty?
    end

    def generate_jti(payload)
      exchange_id = payload[:token_exchange_id] || payload["token_exchange_id"]
      exchange_id ? Digest::SHA256.hexdigest("#{super}:#{exchange_id}") : super
    end

    def oauth_token_subject
      token = authorization_token
      if token && token[oauth_grants_type_column] == TokenExchange::GRANT_TYPE
        return oauth_token_exchange_context(token)["sub"]
      end
      super
    end

    def post_configure
      super
      if is_authorization_server? && features.include?(:oauth_assertion_base)
        raise Rodauth::ConfigurationError, "oauth_token_exchange cannot be combined with oauth_assertion_base (including oauth_jwt_bearer_grant)"
      end
      composed = %i[oauth_jwt oauth_token_introspection oauth_resource_indicators oauth_tls_client_auth oauth_dpop
                    oauth_pkce oauth_device_code_grant]
      if composed.any? { |feature| features.include?(feature) && features.index(feature) > features.index(:oauth_token_exchange) }
        raise Rodauth::ConfigurationError, "enable oauth_token_exchange after the other OAuth features"
      end
      return unless is_authorization_server?

      grant_keys = [oauth_grants_oauth_application_id_column, oauth_grants_account_id_column,
                    oauth_grants_scopes_column, oauth_grants_type_column]
      incompatible_index = db.indexes(oauth_grants_table).values.any? do |index|
        index[:unique] && !index[:columns].empty? && (index[:columns] - grant_keys).empty?
      end
      if __one_oauth_token_per_account || incompatible_index
        raise Rodauth::ConfigurationError, "token exchange requires multiple grants per account/client; remove the unique grant index"
      end
      unless db.schema(oauth_grants_table).any? { |column, _| column == oauth_grants_token_exchange_context_column }
        raise Rodauth::ConfigurationError, "add the token exchange context column before enabling oauth_token_exchange"
      end
    end

    def json_token_introspect_payload(grant)
      if features.include?(:oauth_jwt) && oauth_jwt_access_tokens && request.path == introspect_path
        stored = oauth_token_exchange_stored_grant(param("token"))
        exchange = stored && stored[oauth_grants_type_column] == TokenExchange::GRANT_TYPE
        # The stored fingerprint authenticates the entire locally minted JWT,
        # including targeted tokens which upstream's client-audience check rejects.
        # Consult this record for revocation just as for an opaque access token.
        if exchange || (grant && grant["token_exchange_id"])
          grant = exchange ? stored : nil
        end
      end
      payload = super
      return payload unless grant && payload[:active]

      if grant["sub"]
        # Decoded JWT claims were already rendered for their issuing client.
        %w[sub act aud].each { |key| payload[key.to_sym] = grant[key] if grant.key?(key) }
        return payload
      end

      application = db[oauth_applications_table]
                    .where(oauth_applications_id_column => grant[oauth_grants_oauth_application_id_column]).first
      if grant[oauth_grants_type_column] == TokenExchange::GRANT_TYPE
        payload[:client_id] = application && application[oauth_applications_client_id_column]
      end
      oauth_token_exchange_claims(grant, application).each { |key, value| payload[key.to_sym] = value }
      payload
    end

    private

    def require_oauth_application
      if request.path == token_path && request.post? && request.media_type == "application/x-www-form-urlencoded" &&
         oauth_token_exchange_candidate?
        @oauth_token_exchange_params = oauth_token_exchange_parameters(true)
      end
      # Only server/trusted middleware may assert transport security. Raw
      # Forwarded headers are client-controlled and must not bypass this check.
      # Other grants and endpoints keep rodauth-oauth's transport behavior.
      if @oauth_token_exchange_params && request.env["rack.url_scheme"] != "https"
        throw_json_response_error(400, "invalid_request")
      end
      super
    rescue Rack::QueryParser::InvalidParameterError, Rack::QueryParser::ParameterTypeError
      redirect_response_error("invalid_request")
    end

    def www_authenticate_header(payload)
      # Authentication can fail before form parsing; do not read params here.
      if request.path == token_path && payload["error"] == "invalid_client" &&
         TokenExchange::ClientAuthentication::BASIC_SCHEME.match?(request.env["HTTP_AUTHORIZATION"].to_s)
        return 'Basic realm="token"'
      end
      super
    end

    def oauth_token_exchange_stored_grant(token)
      column = oauth_grants_token_hash_column || oauth_grants_token_column
      value = oauth_grants_token_hash_column ? generate_token_hash(token) : token
      # Reapply validity and exact-token predicates after feature-specific lookup
      # filters; an OR in another feature must never broaden this selection.
      oauth_grant_by_token_ds(token).where(column => value, oauth_grants_revoked_at_column => nil)
                                   .where(Sequel[oauth_grants_expires_in_column] > Sequel::CURRENT_TIMESTAMP).first
    end

    def validate_token_params
      super
      return unless param("grant_type") == TokenExchange::GRANT_TYPE

      @oauth_token_exchange_params ||= oauth_token_exchange_parameters
      params = @oauth_token_exchange_params
      redirect_response_error("invalid_request") unless request.env["rack.url_scheme"] == "https"
      %w[subject_token subject_token_type].each do |key|
        redirect_response_error("invalid_request") unless params[key]
      end
      if params.key?("actor_token") != params.key?("actor_token_type")
        redirect_response_error("invalid_request")
      end
      if params["requested_token_type"] && params["requested_token_type"] != TokenExchange::ACCESS_TOKEN_TYPE
        redirect_response_error("invalid_request")
      end
    rescue Rack::QueryParser::InvalidParameterError, Rack::QueryParser::ParameterTypeError
      # Rack parses params in super, before the exchange-specific wire parser.
      redirect_response_error("invalid_request")
    end

    # Exchange-specific form limits must not change other grants. Scan the whole
    # body, leniently decoding valid escapes, for any occurrence of the grant
    # type; a match in any name or encoding gets the strict exchange parser.
    def oauth_token_exchange_candidate?
      input = request.body
      input.rewind
      overlap = TokenExchange::GRANT_TYPE.bytesize * 3
      tail = String.new(encoding: Encoding::BINARY)
      while (chunk = input.read(64 * 1024))
        window = tail + chunk.b
        decoded = window.gsub(/%(\h\h)/n) { Regexp.last_match(1).hex.chr }
        return true if decoded.include?(TokenExchange::GRANT_TYPE)

        tail = window.byteslice(-[overlap, window.bytesize].min, overlap)
      end
      false
    ensure
      input&.rewind
    end

    def oauth_token_exchange_parameters(only_if_exchange = false)
      redirect_response_error("invalid_request") unless request.media_type == "application/x-www-form-urlencoded"
      # Rack's nested parameter parser discards repeated bare keys. Parse the wire
      # representation to retain RFC 8693 resource/audience multiplicity.
      input = request.body
      input.rewind
      parser = Rack::Utils.default_query_parser
      limit = TokenExchange::MAX_FORM_BYTES
      limit = [limit, parser.bytesize_limit].min if parser.respond_to?(:bytesize_limit)
      raw = input.read(limit + 1)
      input.rewind
      redirect_response_error("invalid_request") if raw.bytesize > limit
      pairs = oauth_token_exchange_form_pairs(raw)
      return if only_if_exchange && !pairs.include?(["grant_type", TokenExchange::GRANT_TYPE])

      names = TokenExchange::SINGLE_PARAMETERS + TokenExchange::TARGET_PARAMETERS + TokenExchange::CLIENT_PARAMETERS
      query_names = oauth_token_exchange_form_pairs(request.query_string).map(&:first)
      redirect_response_error("invalid_request") unless (query_names & names).empty?
      params = {}
      seen = {}
      pairs.each do |name, value|
        value ||= String.new
        name.force_encoding(Encoding::UTF_8)
        value.force_encoding(Encoding::UTF_8)
        redirect_response_error("invalid_request") unless name.valid_encoding? && value.valid_encoding?
        # OAuth parameter names are flat: unknown names (including brackets)
        # are ignored, never interpreted by Rack as arrays or nested objects.
        next unless names.include?(name)

        target = TokenExchange::TARGET_PARAMETERS.include?(name)
        redirect_response_error("invalid_request") if !target && seen[name]
        seen[name] = true
        next if value.empty?

        if target
          (params[name] ||= []) << value
        else
          params[name] = value
        end
      end
      redirect_response_error("invalid_request") unless params["grant_type"] == TokenExchange::GRANT_TYPE
      params
    rescue ArgumentError
      redirect_response_error("invalid_request")
    end

    def oauth_token_exchange_form_pairs(raw)
      if raw.bytesize > TokenExchange::MAX_FORM_BYTES || raw.count("&") >= TokenExchange::MAX_FORM_PARAMETERS ||
         raw.match?(/%(?![0-9a-fA-F]{2})/)
        redirect_response_error("invalid_request")
      end
      parser = Rack::Utils.default_query_parser
      if parser.respond_to?(:parse_query_pairs)
        # Preserve repeated flat keys while retaining Rack's configured limits.
        parser.parse_query_pairs(raw)
      else
        # Older Rack versions have no pair parser. Validate their flat-parser
        # limits before decoding again to retain repeated keys and raw bytes.
        parser.parse_query(raw)
        URI.decode_www_form(raw, Encoding::ASCII_8BIT)
      end
    rescue Rack::QueryParser::ParamsTooDeepError, ArgumentError
      redirect_response_error("invalid_request")
    end

    def create_token(grant_type)
      return super unless grant_type == TokenExchange::GRANT_TYPE

      redirect_response_error("unauthorized_client") unless supported_grant_type?(grant_type)
      params = @oauth_token_exchange_params
      subject = oauth_token_exchange_identity(params["subject_token"], params["subject_token_type"])
      actor = oauth_token_exchange_identity(params["actor_token"], params["actor_token_type"]) if params["actor_token"]
      redirect_response_error("invalid_request") unless oauth_token_exchange_authorized?(subject, actor)

      resources = oauth_token_exchange_targets(params, "resource", :resources, subject, actor)
      audiences = oauth_token_exchange_targets(params, "audience", :audiences, subject, actor)
      targets = (resources + audiences).uniq
      [subject, actor].compact.each do |identity|
        bound = identity.fetch(:resources, []) + identity.fetch(:audiences, [])
        if !bound.empty? && !(targets - bound).empty?
          redirect_response_error("invalid_target")
        end
      end
      resources.each do |resource|
        begin
          uri = URI.parse(resource)
          redirect_response_error("invalid_target") unless uri.absolute? && !uri.fragment
        rescue URI::InvalidURIError
          redirect_response_error("invalid_target")
        end
      end
      unless oauth_token_exchange_targets_allowed?(resources, audiences, subject, actor)
        redirect_response_error("invalid_target")
      end
      scope = oauth_token_exchange_scopes(params["scope"], subject, actor)
      expirations = [Time.now.to_i + oauth_access_token_expires_in, subject[:expires_at]]
      expirations << actor[:expires_at] if actor
      @oauth_token_exchange_expires_at = expirations.min
      redirect_response_error("invalid_request") unless @oauth_token_exchange_expires_at > Time.now.to_i
      extend(TokenExchange::TokenSettings)

      context = {"sub" => subject[:subject], "resource" => resources, "audience" => audiences}
      context["aud"] = targets unless targets.empty?
      context["act"] = subject[:act] if subject[:act]
      # Local account IDs aligned with the actor chain (outermost first) allow
      # pairwise clients to receive their own identifiers for local actors.
      act_account_ids = subject.fetch(:act_account_ids, [])
      if actor
        context["act"] = {"sub" => actor[:subject], "iss" => actor[:issuer], "act" => context["act"]}.compact
        act_account_ids = [actor[:account_id]] + act_account_ids
      else
        # A delegation permission is consumed by the exchange that adds an actor.
        # Store the issuer with it so the namespace survives later exchanges.
        may_act = oauth_token_exchange_may_act(subject)
        context["may_act"] = may_act.compact if may_act
      end
      context["act_account_ids"] = act_account_ids if act_account_ids.any?
      history = context["act"]
      depth = 0
      while history
        depth += 1
        unless history.is_a?(Hash) && depth <= TokenExchange::MAX_ACTOR_DEPTH
          redirect_response_error("invalid_request")
        end
        history = history["act"]
      end

      grant_params = {
        oauth_grants_type_column => TokenExchange::GRANT_TYPE,
        oauth_grants_account_id_column => subject[:account_id],
        oauth_grants_oauth_application_id_column => oauth_application[oauth_applications_id_column],
        oauth_grants_scopes_column => scope.join(oauth_scope_separator),
        oauth_grants_token_exchange_context_column => JSON.generate(context)
      }
      if features.include?(:oauth_resource_indicators) && !targets.empty?
        grant_params[oauth_grants_resource_column] = targets.join(" ")
      end
      generate_token(grant_params, false)
    end

    def oauth_token_exchange_identity(token, type)
      identity = oauth_token_exchange_resolve_token(token, type)
      unless identity.is_a?(Hash) && identity[:subject].is_a?(String) && !identity[:subject].empty? &&
             identity[:scopes].is_a?(Array) && identity[:scopes].all? { |scope| scope.is_a?(String) } &&
             identity[:expires_at].is_a?(Integer) && identity[:expires_at] > Time.now.to_i &&
             (identity[:issuer].nil? || (identity[:issuer].is_a?(String) && !identity[:issuer].empty?)) &&
             (identity[:may_act].nil? || identity[:may_act].is_a?(Hash)) &&
             (identity[:act_account_ids].nil? || identity[:act_account_ids].is_a?(Array))
        redirect_response_error("invalid_request")
      end
      identity
    end

    def oauth_token_exchange_targets(params, parameter, key, subject, actor)
      bound = [subject, actor].compact.map { |identity| identity.fetch(key, []) }.reject(&:empty?).reduce(:&)
      targets = params[parameter] || bound || []
      # An empty intersection must not erase an existing target restriction.
      if bound && (targets.empty? || !(targets - bound).empty?)
        redirect_response_error("invalid_target")
      end
      targets.uniq
    end

    def oauth_token_exchange_scopes(requested, subject, actor)
      allowed = subject[:scopes] & oauth_application[oauth_applications_scopes_column].to_s.split(oauth_scope_separator)
      allowed &= actor[:scopes] if actor
      redirect_response_error("invalid_scope") if allowed.empty?
      return allowed unless requested

      # RFC 6749 scope-token: printable ASCII excluding double quote and backslash.
      unless requested.match?(/\A[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*\z/)
        redirect_response_error("invalid_scope")
      end
      selected = requested.split(" ").uniq
      redirect_response_error("invalid_scope") unless (selected - allowed).empty?
      selected
    end

    def store_token(grant_params, update_params = {})
      if grant_params[oauth_grants_type_column] == TokenExchange::GRANT_TYPE
        redirect_response_error("invalid_request") unless @oauth_token_exchange_expires_at > Time.now.to_i
        update_params = update_params.merge(oauth_grants_expires_in_column => Time.at(@oauth_token_exchange_expires_at))
      end
      super(grant_params, update_params)
    end

    def generate_token(grant_params = {}, should_generate_refresh_token = true)
      grant = super
      if grant_params[oauth_grants_type_column] == TokenExchange::GRANT_TYPE &&
         features.include?(:oauth_jwt) && oauth_jwt_access_tokens
        # Upstream JWT issuance does not persist the access token. Retain its
        # fingerprint so later exchanges can check revocation and exact identity.
        token = grant[oauth_grants_token_column]
        column = oauth_grants_token_hash_column || oauth_grants_token_column
        value = oauth_grants_token_hash_column ? generate_token_hash(token) : token
        db[oauth_grants_table].where(oauth_grants_id_column => grant[oauth_grants_id_column]).update(column => value)
      end
      grant
    end

    def json_access_token_payload(grant)
      payload = super
      if grant[oauth_grants_type_column] == TokenExchange::GRANT_TYPE
        payload["issued_token_type"] = TokenExchange::ACCESS_TOKEN_TYPE
        payload["scope"] = grant[oauth_grants_scopes_column]
      end
      payload
    end

    def jwt_claims(grant)
      claims = super
      context = oauth_token_exchange_context(grant)
      oauth_token_exchange_claims(grant, oauth_application, context).each { |key, value| claims[key.to_sym] = value }
      if grant[oauth_grants_type_column] == TokenExchange::GRANT_TYPE
        claims[:exp] = grant[oauth_grants_expires_in_column].to_time.to_i
        claims[:token_exchange_id] = grant[oauth_grants_id_column].to_s
        claims[:resource] = context["aud"] if context["aud"]
      end
      claims
    end

    def oauth_token_exchange_context(grant)
      value = grant[oauth_grants_token_exchange_context_column]
      value ? JSON.parse(value) : {}
    end

    # Context stores subject identifiers as resolved (public for local
    # accounts). Pairwise clients receive their own sector identifiers for the
    # subject and local actors, matching upstream JWT access-token subjects.
    def oauth_token_exchange_claims(grant, application, context = oauth_token_exchange_context(grant))
      claims = context.slice("sub", "act", "aud")
      return claims unless oauth_token_exchange_pairwise?(application)

      account = grant[oauth_grants_account_id_column]
      claims["sub"] = jwt_subject(account, application) if account && claims.key?("sub")
      if claims["act"]
        claims["act"] = oauth_token_exchange_pairwise_act(claims["act"], context.fetch("act_account_ids", []), application)
      end
      claims
    end

    def oauth_token_exchange_pairwise?(application)
      return false unless application && features.include?(:oidc)

      (application[oauth_applications_subject_type_column] || oauth_jwt_subject_type) == "pairwise"
    end

    def oauth_token_exchange_pairwise_act(act, account_ids, application)
      return act unless act.is_a?(Hash)

      account, *older = account_ids
      act = act.merge("sub" => jwt_subject(account, application)) if account && !act.key?("iss")
      act = act.merge("act" => oauth_token_exchange_pairwise_act(act["act"], older, application)) if act["act"]
      act
    end
  end
end
