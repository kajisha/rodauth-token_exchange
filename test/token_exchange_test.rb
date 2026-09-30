# frozen_string_literal: true

require_relative "test_helper"

class TokenExchangeTest < ExchangeTest
  def test_form_only_and_query_parameters_rejected
    params = {grant_type: GRANT, subject_token: "subject-token", subject_token_type: ACCESS}
    post "/token", JSON.generate(params), "CONTENT_TYPE" => "application/json"
    assert_error "invalid_request"
    post "/token?subject_token=query-token", URI.encode_www_form(params), "CONTENT_TYPE" => "application/x-www-form-urlencoded"
    assert_error "invalid_request"
  end

  def test_malformed_scope_and_structured_parameters
    ["read\twrite", "read  write", " read", 'read"', "read\\write"].each do |scope|
      exchange(scope: scope)
      assert_error "invalid_scope"
    end
    [{scope: ["read"]}, {resource: ["https://api.example.com"]}, {audience: {name: "api"}}].each do |params|
      exchange(params)
      assert_equal 200, last_response.status
      assert_equal "read write", body["scope"]
    end
  end

  def test_metadata_and_other_grants
    get "/.well-known/oauth-authorization-server"
    assert_includes body["grant_types_supported"], GRANT
    post "/token", grant_type: "client_credentials", scope: "read"
    assert_equal 200, last_response.status
    refute body.key?("issued_token_type")
  end

  def test_invalid_subject_tokens
    ["unknown", "", nil].each do |token|
      exchange(subject_token: token)
      assert_error "invalid_request"
    end
    db[:oauth_grants].where(id: @source_id).update(expires_in: Time.now - 1)
    exchange
    assert_error "invalid_request"
    db[:oauth_grants].where(id: @source_id).update(expires_in: Time.now + 1800, revoked_at: Time.now)
    exchange
    assert_error "invalid_request"
  end

  def test_types_and_actor_pairing
    [{subject_token_type: nil}, {subject_token_type: "jwt"},
     {requested_token_type: "urn:ietf:params:oauth:token-type:refresh_token"},
     {actor_token: "actor"}, {actor_token_type: ACCESS}, {subject_token: ["a"]}].each do |params|
      exchange(params)
      assert_error "invalid_request"
    end
  end

  def test_scope_is_bounded_by_subject_and_client
    exchange(scope: "admin")
    assert_error "invalid_scope"
    db[:oauth_grants].where(id: @source_id).update(scopes: "read")
    exchange(scope: "write")
    assert_error "invalid_scope"
    db[:oauth_applications].where(id: 1).update(scopes: "write")
    exchange(scope: "read")
    assert_error "invalid_scope"
  end

  def test_scope_default_is_intersection
    db[:oauth_applications].where(id: 1).update(scopes: "read")
    exchange
    assert_equal 200, last_response.status
    assert_equal "read", body["scope"]
  end

  def test_client_authentication_and_grant_authorization
    basic_authorize "client", "wrong"
    exchange
    assert_equal 401, last_response.status
    basic_authorize "other", "secret"
    exchange
    assert_error "invalid_request"
    basic_authorize "client", "secret"
    db[:oauth_applications].where(id: 1).update(grant_types: "client_credentials")
    exchange
    assert_error "unauthorized_client"
  end

  def test_targets_and_actor_are_denied_by_default
    exchange(resource: "https://api.example.com")
    assert_error "invalid_target"
    exchange(audience: "api")
    assert_error "invalid_target"
    seed_token("actor-token", account_id: 2)
    exchange(actor_token: "actor-token", actor_token_type: ACCESS)
    assert_error "invalid_request"
  end

  def test_duplicate_singletons_and_invalid_resources
    raw = URI.encode_www_form(grant_type: GRANT, subject_token: "subject-token", subject_token_type: ACCESS)
    post "/token", raw + "&subject_token=other", "CONTENT_TYPE" => "application/x-www-form-urlencoded"
    assert_error "invalid_request"
    ["relative", "https://api.example.com/#fragment"].each do |resource|
      exchange(resource: resource)
      assert_error "invalid_target"
    end
  end

  def test_exchange_creates_a_new_hashed_access_token_without_mutating_source
    source = db[:oauth_grants][id: @source_id]
    exchange(scope: "read")
    assert_equal 200, last_response.status, last_response.body
    assert_equal ACCESS, body["issued_token_type"]
    assert_equal "bearer", body["token_type"].downcase
    assert_equal "read", body["scope"]
    refute body.key?("refresh_token")
    assert_operator body["expires_in"], :>, 0
    assert_operator body["expires_in"], :<=, 1800
    grant = db[:oauth_grants][token: hash_token(body["access_token"])]
    assert grant
    assert_equal GRANT, grant[:type]
    assert_equal 1, grant[:account_id]
    assert_equal source, db[:oauth_grants][id: @source_id]
    assert_match(/no-store/, last_response.headers["cache-control"])
  end
end
