# frozen_string_literal: true

require_relative "test_helper"
require "jwt"

class ResourceAuthorizationTest < ExchangeTest
  KEY = "resource-boundary-signing-key-" * 3

  def target_token(resource, jwt: false, dpop: false)
    db.alter_table(:oauth_grants) { add_column :resource, String } unless db.schema(:oauth_grants).any? { |column, _| column == :resource }
    db.alter_table(:oauth_grants) { add_column :dpop_jkt, String } if dpop
    resources = Array(resource)
    features = (jwt ? [:oauth_jwt] : []) + [:oauth_resource_indicators] + (dpop ? [:oauth_dpop] : [])
    build_app(*features) do
      oauth_jwt_keys("HS256" => KEY) if jwt
      oauth_token_exchange_targets_allowed? { |requested, audiences, _s, _a| requested == resources && audiences.empty? }
    end
    app.route do |r|
      r.rodauth
      r.get do
        rodauth.require_oauth_authorization("read")
        rodauth.oauth_token_subject.to_s
      end
    end
    basic_authorize "client", "secret"
    post "/token", URI.encode_www_form([
      ["grant_type", GRANT], ["subject_token", "subject-token"], ["subject_token_type", ACCESS],
      *resources.map { |target| ["resource", target] }
    ]), "CONTENT_TYPE" => "application/x-www-form-urlencoded"
    assert_equal 200, last_response.status, last_response.body
    body.fetch("access_token")
  end

  def access(token, url)
    header "Authorization", "Bearer #{token}"
    env "rack.url_scheme", URI.parse(url).scheme
    get url
  end

  def test_opaque_target_requires_the_same_origin
    token = target_token("https://example.org")
    access(token, "https://example.org/protected")
    assert_equal 200, last_response.status
    ["https://example.org.attacker.example/protected", "http://example.org/protected",
     "https://example.org:444/protected", "https://other.example/protected"].each do |url|
      access(token, url)
      assert_equal 401, last_response.status, url
    end
    access(token, "https://example.org:443/protected")
    assert_equal 200, last_response.status
  end

  def test_jwt_target_is_usable_only_at_the_same_origin
    token = target_token("https://example.org", jwt: true)
    access(token, "https://example.org/protected")
    assert_equal 200, last_response.status
    access(token, "https://example.org.attacker.example/protected")
    assert_equal 401, last_response.status
    access(token, "http://example.org/protected")
    assert_equal 401, last_response.status
    access(token, "https://example.org:444/protected")
    assert_equal 401, last_response.status
  end

  def test_path_resource_is_usable_at_its_exact_path
    [false, true].each do |jwt|
      token = target_token("https://example.org/protected", jwt: jwt)
      access(token, "https://example.org/protected")
      assert_equal 200, last_response.status
      access(token, "https://example.org/protected/child")
      assert_equal 200, last_response.status
    end
  end

  def test_path_resource_cannot_escape_to_a_sibling_or_parent
    [false, true].each do |jwt|
      token = target_token("https://example.org/pro", jwt: jwt)
      access(token, "https://example.org/protected")
      assert_equal 401, last_response.status
      token = target_token("https://example.org/protected", jwt: jwt)
      ["https://example.org/protected/../admin", "https://example.org/protected/%2e%2e/admin",
       "https://example.org/protected/%2F..%2Fadmin", "https://example.org/protected/%5C..%5Cadmin"].each do |url|
        access(token, url)
        assert_equal 401, last_response.status, url
      end
      token = target_token("https://example.org/protected/../admin", jwt: jwt)
      access(token, "https://example.org/protected")
      assert_equal 401, last_response.status
    end
  end

  def test_resource_query_must_match_when_specified
    [false, true].each do |jwt|
      token = target_token("https://example.org/protected?tenant=1", jwt: jwt)
      access(token, "https://example.org/protected?tenant=1")
      assert_equal 200, last_response.status
      access(token, "https://example.org/protected?tenant=2")
      assert_equal 401, last_response.status
    end
  end

  def test_multiple_matching_resources_do_not_reject_a_valid_token
    token = target_token(["https://example.org", "https://example.org/protected"], jwt: true)
    access(token, "https://example.org/protected")
    assert_equal 200, last_response.status
  end

  def test_scope_checks_are_preserved
    token = target_token("https://example.org")
    db[:oauth_grants].where(token: hash_token(token)).update(scopes: "write")
    access(token, "https://example.org/protected")
    assert_equal 401, last_response.status
  end

  def test_dpop_sender_binding_checks_are_preserved
    token = target_token("https://example.org", jwt: true, dpop: true)
    claims, = JWT.decode(token, KEY, true, algorithms: ["HS256"])
    claims["cnf"] = {"jkt" => "bound-key"}
    bound = JWT.encode(claims, KEY, "HS256", typ: "at+jwt")
    access(bound, "https://example.org/protected")
    assert_error "access_token_dpop_bound", 401
  end

  def test_invalid_jwt_is_rejected_without_an_exception
    target_token("https://example.org", jwt: true)
    access("not-a-jwt", "https://example.org/protected")
    assert_equal 401, last_response.status
  end

  def test_resource_server_checks_introspected_targets
    build_app(:oauth_resource_server, :oauth_resource_indicators)
    payload = {"active" => true, "scope" => "read", "sub" => "1", "aud" => ["https://example.org/protected"]}
    # Replace only the HTTP boundary; use the real resource-server and resource
    # indicators authorization chain on the introspection response.
    app.rodauth.send(:define_method, :introspection_request) do |_hint, _token|
      payload.merge(oauth_grants_resource_column => payload["aud"])
    end
    access("introspected-token", "https://example.org/protected")
    assert_equal 200, last_response.status
    access("introspected-token", "https://example.org.attacker.example/protected")
    assert_equal 401, last_response.status
  end

  def test_resource_context_remains_available_after_authorization
    token = target_token("https://example.org/protected", jwt: true)
    app.route do |r|
      r.get do
        rodauth.require_oauth_authorization("read")
        JSON.generate(rodauth.send(:authorization_token)["resource"])
      end
    end
    access(token, "https://example.org/protected")
    assert_equal 200, last_response.status
    assert_equal ["https://example.org/protected"], body
  end

  def test_resource_server_rejects_late_resource_feature
    assert_raises(Rodauth::ConfigurationError) do
      build_app(:oauth_resource_server) { enable :oauth_resource_indicators }
    end
  end

  def test_jwt_signature_and_expiration_checks_are_preserved
    token = target_token("https://example.org", jwt: true)
    claims, = JWT.decode(token, KEY, true, algorithms: ["HS256"])
    claims["exp"] = Time.now.to_i - 10
    expired = JWT.encode(claims, KEY, "HS256", typ: "at+jwt")
    access(expired, "https://example.org/protected")
    assert_equal 401, last_response.status
    access(JWT.encode(claims.merge("exp" => Time.now.to_i + 100), "wrong-key", "HS256", typ: "at+jwt"), "https://example.org/protected")
    assert_equal 401, last_response.status
  end
end
