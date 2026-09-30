# frozen_string_literal: true

require_relative "test_helper"
require "jwt"

class ExtensionsTest < ExchangeTest
  KEY = "test-signing-key-" * 4

  def test_introspection_reports_issuing_client_not_requesting_client
    [false, true].each do |jwt|
      build_app(*(jwt ? [:oauth_jwt] : [])) { oauth_jwt_keys("HS256" => KEY) if jwt }
      basic_authorize "client", "secret"
      exchange
      token = body.fetch("access_token")
      basic_authorize "other", "secret"
      post "/introspect", token: token
      assert_equal true, body["active"]
      assert_equal "client", body["client_id"]
    end
  end

  def test_configured_lifetime_cannot_exceed_input_lifetimes
    build_app(:oauth_jwt) do
      oauth_jwt_keys("HS256" => KEY)
      oauth_access_token_expires_in 7200
      oauth_token_exchange_authorized? { |_subject, _actor| true }
    end
    basic_authorize "client", "secret"
    seed_token("actor-token", account_id: 2, expires_in: Time.now + 120)
    exchange(actor_token: "actor-token", actor_token_type: ACCESS)
    assert_equal 200, last_response.status
    assert_operator body["expires_in"], :<=, 120
    claims, = JWT.decode(body["access_token"], KEY, true, algorithms: ["HS256"])
    assert_operator claims["exp"], :<=, Time.now.to_i + 120
    grant = db[:oauth_grants][token: hash_token(body["access_token"])]
    assert_operator grant[:expires_in].to_time.to_i, :<=, Time.now.to_i + 120
    post "/token", grant_type: "client_credentials"
    assert_equal 7200, body["expires_in"]
  end

  def test_configured_reuse_cannot_select_an_unrelated_grant
    seed_token("unrelated", account_id: nil, oauth_application_id: nil, scopes: nil)
    build_app { oauth_reuse_access_token true }
    basic_authorize "client", "secret"
    exchange(scope: "read")
    assert_equal 200, last_response.status
    assert_equal ACCESS, body["issued_token_type"]
    assert_equal "read", body["scope"]
    grant = db[:oauth_grants][token: hash_token(body["access_token"])]
    assert_equal 1, grant[:account_id]
  end

  def test_jwt_output_preserves_subject_actor_audience_and_lifetime
    build_app(:oauth_jwt) do
      oauth_jwt_keys("HS256" => KEY)
      oauth_token_exchange_authorized? { |_subject, _actor| true }
      oauth_token_exchange_targets_allowed? { |resources, audiences, _subject, _actor| resources == ["https://api.example.com"] && audiences.empty? }
    end
    basic_authorize "client", "secret"
    seed_token("actor-token", account_id: 2, expires_in: Time.now + 300)
    exchange(actor_token: "actor-token", actor_token_type: ACCESS, resource: "https://api.example.com")
    assert_equal 200, last_response.status, last_response.body
    assert_equal ACCESS, body["issued_token_type"]
    claims, header = JWT.decode(body["access_token"], KEY, true, algorithms: ["HS256"])
    assert_equal "at+jwt", header["typ"]
    assert_equal "1", claims["sub"]
    assert_equal({"sub" => "2"}, claims["act"])
    assert_equal ["https://api.example.com"], claims["aud"]
    assert_operator claims["exp"], :<=, Time.now.to_i + 300
    post "/introspect", token: body["access_token"]
    assert_equal true, body["active"]
    assert_equal({"sub" => "2"}, body["act"])
  end

  def test_custom_validated_token_resolver
    build_app do
      oauth_token_exchange_resolve_token do |token, type|
        if type == "urn:example:trusted" && token == "trusted-token"
          {subject: "external-user", account_id: 1, application_id: 1,
           scopes: ["read"], expires_at: Time.now.to_i + 120}
        else
          super(token, type)
        end
      end
    end
    basic_authorize "client", "secret"
    exchange(subject_token: "trusted-token", subject_token_type: "urn:example:trusted")
    assert_equal 200, last_response.status
    post "/introspect", token: body["access_token"]
    assert_equal "external-user", body["sub"]
    exchange(subject_token: "bad-token", subject_token_type: "urn:example:trusted")
    assert_error "invalid_request"
  end

  def test_plaintext_storage_configuration
    db[:oauth_grants].where(id: @source_id).update(token: "subject-token")
    build_app { oauth_grants_token_hash_column nil }
    basic_authorize "client", "secret"
    exchange
    assert_equal 200, last_response.status
    assert db[:oauth_grants][token: body["access_token"]]
  end

  def test_client_subject_survives_cross_client_exchange
    db[:oauth_grants].where(id: @source_id).update(account_id: nil)
    build_app { oauth_token_exchange_authorized? { |_subject, _actor| true } }
    basic_authorize "other", "secret"
    exchange
    assert_equal 200, last_response.status
    post "/introspect", token: body["access_token"]
    assert_equal "client", body["sub"]
  end

  def test_resource_server_sees_original_client_subject
    db[:oauth_grants].where(id: @source_id).update(account_id: nil)
    build_app { oauth_token_exchange_authorized? { |_subject, _actor| true } }
    basic_authorize "other", "secret"
    exchange
    header "Authorization", "Bearer #{body.fetch('access_token')}"
    get "/protected"
    assert_equal 200, last_response.status
    assert_equal "client", last_response.body
  end

  def test_resource_server_rejects_wrong_target
    db.alter_table(:oauth_grants) { add_column :resource, String }
    build_app(:oauth_resource_indicators) do
      oauth_token_exchange_targets_allowed? { |resources, audiences, _s, _a| resources == ["https://example.org"] && audiences.empty? }
    end
    basic_authorize "client", "secret"
    exchange(resource: "https://example.org")
    header "Authorization", "Bearer #{body.fetch('access_token')}"
    get "https://example.org/protected"
    assert_equal 200, last_response.status
    get "https://other.example.com/protected"
    assert_equal 401, last_response.status
  end

  def test_unique_account_client_schema_is_rejected
    db.add_index(:oauth_grants, [:oauth_application_id, :account_id], unique: true)
    assert_raises(Rodauth::ConfigurationError) { build_app }
  end

  def test_feature_order_is_checked
    assert_raises(Rodauth::ConfigurationError) do
      build_app do
        enable :oauth_jwt
        oauth_jwt_keys("HS256" => KEY)
      end
    end
  end

  def test_missing_context_column_is_reported_at_configuration
    db.alter_table(:oauth_grants) { drop_column :token_exchange_context }
    assert_raises(Rodauth::ConfigurationError) { build_app }
  end

  def test_authentication_features_cannot_override_exchange_by_loading_later
    %i[oauth_pkce oauth_device_code_grant].each do |feature|
      error = assert_raises(Rodauth::ConfigurationError) { build_app { enable feature } }
      assert_includes error.message, "enable oauth_token_exchange after"
    end
  end

  def test_assertion_grant_composition_is_rejected_at_configuration
    [false, true].each do |late|
      error = assert_raises(Rodauth::ConfigurationError) do
        build_app(*(late ? [] : [:oauth_jwt_bearer_grant])) do
          enable :oauth_jwt_bearer_grant if late
          oauth_jwt_keys("HS256" => KEY)
        end
      end
      assert_includes error.message, "oauth_assertion_base"
    end
  end

  def test_native_resource_constraints_are_preserved
    db.alter_table(:oauth_grants) { add_column :resource, String }
    db[:oauth_grants].where(id: @source_id).update(resource: "https://api.example.com")
    build_app(:oauth_resource_indicators) do
      oauth_token_exchange_targets_allowed? { |resources, audiences, _s, _a| resources == ["https://api.example.com"] && audiences.empty? }
    end
    basic_authorize "client", "secret"
    exchange
    assert_equal 200, last_response.status, last_response.body
    grant = db[:oauth_grants][token: hash_token(body["access_token"])]
    assert_equal "https://api.example.com", grant[:resource]
    exchange(resource: "https://elsewhere.example.com")
    assert_error "invalid_target"
  end

  def test_sender_constrained_source_is_not_downgraded
    db.alter_table(:oauth_grants) { add_column :certificate_thumbprint, String }
    db[:oauth_grants].where(id: @source_id).update(certificate_thumbprint: "bound-key")
    exchange
    assert_error "invalid_request"
  end

  def test_dpop_bound_source_is_not_downgraded
    db.alter_table(:oauth_grants) { add_column :dpop_jkt, String }
    db[:oauth_grants].where(id: @source_id).update(dpop_jkt: "bound-key")
    exchange
    assert_error "invalid_request"
  end

  def test_context_column_is_configurable
    db.alter_table(:oauth_grants) { rename_column :token_exchange_context, :exchange_context }
    build_app { oauth_grants_token_exchange_context_column :exchange_context }
    basic_authorize "client", "secret"
    exchange
    assert_equal 200, last_response.status
    grant = db[:oauth_grants][token: hash_token(body["access_token"])]
    assert_equal "1", JSON.parse(grant[:exchange_context])["sub"]
  end

  def test_existing_refresh_flow_is_unchanged
    db[:oauth_grants].where(id: @source_id).update(refresh_token: hash_token("refresh-token"))
    post "/token", grant_type: "refresh_token", refresh_token: "refresh-token"
    assert_equal 200, last_response.status, last_response.body
    assert body["refresh_token"]
    refute body.key?("issued_token_type")
  end

  def test_jwt_exchange_output_can_be_exchanged_again_and_revoked
    build_app(:oauth_jwt) { oauth_jwt_keys("HS256" => KEY) }
    basic_authorize "client", "secret"
    exchange
    token = body.fetch("access_token")
    exchange(subject_token: token)
    assert_equal 200, last_response.status, last_response.body
    db[:oauth_grants].where(token: hash_token(token)).update(revoked_at: Time.now)
    post "/introspect", token: token
    assert_equal false, body["active"]
    exchange(subject_token: token)
    assert_error "invalid_request"
  end
end
