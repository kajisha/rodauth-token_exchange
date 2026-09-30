# frozen_string_literal: true

require_relative "test_helper"
require "jwt"

class SecurityBoundsTest < ExchangeTest
  def test_delayed_issuance_preserves_absolute_expiry_in_database_and_jwt
    [false, true].each do |jwt|
      build_app(*(jwt ? [:oauth_jwt] : [])) do
        oauth_jwt_keys("HS256" => "test-signing-key-" * 4) if jwt
      end
      basic_authorize "client", "secret"
      source_expiry = db[:oauth_grants][id: @source_id][:expires_in].to_time.to_i
      app.rodauth.prepend(Module.new do
        def generate_token(*args)
          sleep 1.1
          super
        end
      end)
      exchange
      assert_equal 200, last_response.status, last_response.body
      grant = db[:oauth_grants][token: hash_token(body.fetch("access_token"))]
      assert_operator grant[:expires_in].to_time.to_i, :<=, source_expiry
      if jwt
        claims, = JWT.decode(body["access_token"], "test-signing-key-" * 4, true, algorithms: ["HS256"])
        assert_operator claims["exp"], :<=, source_expiry
        assert_equal grant[:expires_in].to_time.to_i, claims["exp"]
      end
    end
  end

  def test_actor_history_limit_rejects_without_issuing_or_truncating
    build_app { oauth_token_exchange_authorized? { |_subject, _actor| true } }
    basic_authorize "client", "secret"
    seed_token("actor", account_id: 2)
    token = "subject-token"
    16.times do
      exchange(subject_token: token, actor_token: "actor", actor_token_type: ACCESS)
      assert_equal 200, last_response.status, last_response.body
      token = body.fetch("access_token")
    end
    # Existing history remains usable without adding another actor.
    exchange(subject_token: token)
    assert_equal 200, last_response.status
    count = db[:oauth_grants].count
    exchange(subject_token: token, actor_token: "actor", actor_token_type: ACCESS)
    assert_error "invalid_request"
    assert_equal count, db[:oauth_grants].count
  end

  def test_expiration_during_issuance_rejects_without_storing_a_grant
    app.rodauth.prepend(Module.new do
      def generate_token(*args)
        Time.stub(:now, Time.now + 3600) { super }
      end
    end)
    count = db[:oauth_grants].count
    exchange
    assert_error "invalid_request"
    assert_equal count, db[:oauth_grants].count
  end

  def test_excessive_form_pairs_are_rejected_before_authentication
    header "Authorization", nil
    assert_rejected_form(base_form + "&ignored=x" * 4100)
  end

  def test_excessive_form_bytes_are_rejected_before_authentication
    header "Authorization", nil
    assert_rejected_form(base_form + "&ignored=" + "x" * (4 * 1024 * 1024))
  end

  def test_configured_rack_pair_limit_is_respected
    original = Rack::Utils.default_query_parser
    Rack::Utils.default_query_parser = Rack::QueryParser.make_default(32, params_limit: 4)
    assert_rejected_form(base_form + "&ignored=x&ignored=y")
  ensure
    Rack::Utils.default_query_parser = original
  end

  def test_configured_rack_byte_limit_is_respected
    original = Rack::Utils.default_query_parser
    Rack::Utils.default_query_parser = Rack::QueryParser.make_default(32, bytesize_limit: 256)
    assert_rejected_form(base_form + "&ignored=" + "x" * 256)
  ensure
    Rack::Utils.default_query_parser = original
  end

  def test_legacy_pair_parser_fallback_preserves_rack_limits
    original = Rack::Utils.default_query_parser
    parser = Rack::QueryParser.make_default(32, params_limit: 4, bytesize_limit: 256)
    parser.singleton_class.send(:undef_method, :parse_query_pairs)
    Rack::Utils.default_query_parser = parser
    assert_rejected_form(base_form + "&ignored=x&ignored=y")
    post "/token?ignored=#{'x' * 256}", base_form,
         "CONTENT_TYPE" => "application/x-www-form-urlencoded"
    assert_error "invalid_request"
  ensure
    Rack::Utils.default_query_parser = original
  end

  private

  def base_form
    URI.encode_www_form(grant_type: GRANT, subject_token: "subject-token", subject_token_type: ACCESS)
  end

  def assert_rejected_form(raw)
    count = db[:oauth_grants].count
    post "/token", raw, "CONTENT_TYPE" => "application/x-www-form-urlencoded"
    assert_error "invalid_request"
    assert_equal count, db[:oauth_grants].count
  end
end
