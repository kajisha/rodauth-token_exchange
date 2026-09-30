# frozen_string_literal: true

require_relative "test_helper"
require "jwt"

# Local equivalents of selected pinned OpenID suite conditions, plus RFC 8693
# boundary cases. See docs/rfc8693-coverage.md for source conditions and limits.
class ConformanceTest < ExchangeTest
  KEY = "conformance-test-signing-key-" * 3

  def test_common_token_response_conditions_for_opaque_and_jwt
    [false, true].each do |jwt|
      build_app(*(jwt ? [:oauth_jwt] : [])) { oauth_jwt_keys("HS256" => KEY) if jwt }
      basic_authorize "client", "secret"
      exchange(scope: "read", requested_token_type: ACCESS)
      assert_equal 200, last_response.status
      assert_json_content_type
      assert_includes last_response.headers.fetch("cache-control").split(",").map(&:strip), "no-store"
      assert_equal "no-cache", last_response.headers["pragma"]
      payload = body
      assert_instance_of String, payload["access_token"]
      assert_match(/\A[\x20-\x7E]+\z/, payload["access_token"])
      assert_instance_of String, payload["token_type"]
      assert_equal "bearer", payload["token_type"].downcase
      assert_equal ACCESS, payload["issued_token_type"]
      assert_instance_of Integer, payload["expires_in"]
      assert_operator payload["expires_in"], :>, 0
      assert_operator payload["expires_in"], :<=, 31_536_000
      assert_instance_of String, payload["scope"]
      assert_equal "read", payload["scope"]
      refute payload.key?("refresh_token")
      if jwt
        claims, = JWT.decode(payload["access_token"], KEY, true, algorithms: ["HS256"])
        assert_equal "read", claims["scope"]
        assert_equal "client", claims["client_id"]
        refute claims.key?("act")
      end
    end
  end

  def test_common_error_response_conditions
    [{subject_token: "invalid"}, {subject_token_type: "unsupported"},
     {requested_token_type: "unsupported"}, {actor_token: "unpaired"},
     {resource: "relative"}, {scope: "admin"}].each do |params|
      exchange(params)
      assert_equal 400, last_response.status
      assert_json_content_type
      assert_error_fields
      refute body.key?("access_token")
    end
    [["client", "wrong"], ["unknown", "secret"]].each do |client, secret|
      basic_authorize client, secret
      exchange
      assert_error "invalid_client", 401
      assert_json_content_type
      assert_error_fields
    end
    header "Authorization", nil
    exchange
    assert_error "invalid_client", 401
  end

  def test_jwt_client_id_identifies_exchange_requester
    build_app(:oauth_jwt) do
      oauth_jwt_keys("HS256" => KEY)
      oauth_token_exchange_authorized? { |_subject, _actor| true }
    end
    basic_authorize "other", "secret"
    exchange(scope: "read")
    assert_equal 200, last_response.status
    token = body.fetch("access_token")
    claims, = JWT.decode(token, KEY, true, algorithms: ["HS256"])
    assert_equal "1", claims["sub"]
    assert_equal "other", claims["client_id"]
    basic_authorize "client", "secret"
    post "/introspect", token: token
    assert_equal "other", body["client_id"]
  end

  def test_basic_authentication_failure_uses_matching_challenge
    basic_authorize "client", "wrong"
    exchange
    assert_error "invalid_client", 401
    assert_match(/\ABasic(?:\s|\z)/i, last_response.headers.fetch("www-authenticate"))
    post_form("grant_type=#{URI.encode_www_form_component(GRANT)}&bad=%ZZ")
    assert_error "invalid_request"
  end

  def test_missing_basic_credentials_use_matching_challenge
    ["Basic", "bAsIc", "Basic ", "Basic\t"].each do |authorization|
      header "Authorization", authorization
      count = db[:oauth_grants].count
      exchange
      assert_error "invalid_client", 401
      assert_equal 'Basic realm="token"', last_response.headers["www-authenticate"]
      assert_equal count, db[:oauth_grants].count
    end
  end

  def test_all_singleton_parameters_reject_duplicates
    allow_targets_and_actors
    seed_token("actor-token", account_id: 2)
    params = {grant_type: GRANT, subject_token: "subject-token", subject_token_type: ACCESS,
              actor_token: "actor-token", actor_token_type: ACCESS, requested_token_type: ACCESS, scope: "read"}
    params.each do |key, value|
      post_form(URI.encode_www_form(params.to_a + [[key, value]]))
      assert_error "invalid_request"
    end
  end

  def test_required_parameters_missing_or_empty
    %i[grant_type subject_token subject_token_type].each do |key|
      [nil, ""].each do |value|
        exchange(key => value)
        assert_error "invalid_request"
      end
    end
  end

  def test_utf8_form_encoding_is_validated_before_policy
    allow_targets_and_actors
    raw = URI.encode_www_form(grant_type: GRANT, subject_token: "subject-token", subject_token_type: ACCESS)
    ["audience=%FF", "audience=%C0%AF", "unknown=%FF", "%FF=value", "audience=%ZZ"].each do |suffix|
      post_form("#{raw}&#{suffix}")
      assert_error "invalid_request"
    end
    post_form("#{raw}&audience=#{URI.encode_www_form_component('対象API')}&unknown=ignored")
    assert_equal 200, last_response.status
    post "/introspect", token: body.fetch("access_token")
    assert_equal ["対象API"], body["aud"]
  end

  def test_resource_uri_syntax_independently_of_policy
    allow_targets_and_actors
    ["relative", "https://api.example.com/#fragment", "https://api.example.com/#", "https://api.example.com/a b"].each do |resource|
      exchange(resource: resource)
      assert_error "invalid_target"
    end
    ["https://api.example.com/path?tenant=1", "urn:example:resource"].each do |resource|
      exchange(resource: resource)
      assert_equal 200, last_response.status
      post "/introspect", token: body.fetch("access_token")
      assert_equal [resource], body["aud"]
    end
  end

  def test_actor_and_subject_remain_valid_after_exchange
    allow_targets_and_actors
    seed_token("actor-token", account_id: 2)
    sources = db[:oauth_grants].order(:id).all
    exchange(actor_token: "actor-token", actor_token_type: ACCESS)
    assert_equal 200, last_response.status
    assert_equal sources, db[:oauth_grants].where(id: sources.map { |row| row[:id] }).order(:id).all
    %w[subject-token actor-token].each do |token|
      post "/introspect", token: token
      assert_equal true, body["active"]
    end
  end

  def test_scope_is_case_sensitive
    exchange(scope: "Read")
    assert_error "invalid_scope"
  end

  def test_empty_scope_intersection_does_not_emit_an_invalid_scope_string
    db[:oauth_grants].where(id: @source_id).update(scopes: "read")
    db[:oauth_applications].where(id: 1).update(scopes: "write")
    exchange
    assert_error "invalid_scope"
    db[:oauth_applications].where(id: 1).update(scopes: "read write")
    allow_targets_and_actors
    seed_token("actor-token", account_id: 2, scopes: "write")
    exchange(actor_token: "actor-token", actor_token_type: ACCESS)
    assert_error "invalid_scope"
  end

  def test_historical_actor_claims_do_not_authorize_or_change_token_bounds
    history = {"sub" => "past-actor", "scope" => "admin", "exp" => 0,
               "aud" => "untrusted-target", "act" => {"sub" => "older-actor",
                 "scope" => "admin", "exp" => 0, "aud" => "another-target"}}
    db[:oauth_grants].where(id: @source_id).update(
      token_exchange_context: JSON.generate("sub" => "1", "act" => history), scopes: "read"
    )
    exchange(scope: "admin")
    assert_error "invalid_scope"
    exchange
    assert_equal 200, last_response.status
    assert_equal "read", body["scope"]
    assert_operator body["expires_in"], :>, 0
    assert_operator body["expires_in"], :<=, 1800
    post "/introspect", token: body.fetch("access_token")
    assert_equal history, body["act"]
    refute body.key?("aud")
  end

  def test_get_cannot_issue_a_token
    count = db[:oauth_grants].count
    get "/token", grant_type: GRANT, subject_token: "subject-token", subject_token_type: ACCESS
    refute_equal 200, last_response.status
    assert_equal count, db[:oauth_grants].count
  end

  private

  def allow_targets_and_actors
    build_app do
      oauth_token_exchange_authorized? { |_subject, _actor| true }
      oauth_token_exchange_targets_allowed? { |_resources, _audiences, _subject, _actor| true }
    end
    basic_authorize "client", "secret"
  end

  def post_form(raw)
    post "/token", raw, "CONTENT_TYPE" => "application/x-www-form-urlencoded"
  end

  def assert_json_content_type
    assert_equal "application/json", last_response.headers.fetch("content-type").split(";").first.strip
  end

  def assert_error_fields
    assert_instance_of String, body["error"]
    assert_match(/\A[\x20-\x21\x23-\x5B\x5D-\x7E]+\z/, body["error"])
    if body.key?("error_description")
      assert_instance_of String, body["error_description"]
      assert_match(/\A[\x20-\x21\x23-\x5B\x5D-\x7E]*\z/, body["error_description"])
    end
    # This profile omits error_uri; its optional-absence path is covered only.
    refute body.key?("error_uri")
  end
end
