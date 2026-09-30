# frozen_string_literal: true

require_relative "test_helper"

class DelegationTest < ExchangeTest
  def enable_policy
    build_app do
      oauth_token_exchange_authorized? { |_subject, _actor| true }
      oauth_token_exchange_targets_allowed? do |resources, audiences, _subject, _actor|
        (resources - %w[https://api.example.com/a https://api.example.com/b]).empty? &&
          (audiences - %w[api worker]).empty?
      end
    end
    basic_authorize "client", "secret"
  end

  def test_delegation_persists_actor_and_repeated_targets_and_introspects
    enable_policy
    seed_token("actor-token", account_id: 2, scopes: "read", expires_in: Time.now + 600)
    params = [
      ["grant_type", GRANT], ["subject_token", "subject-token"], ["subject_token_type", ACCESS],
      ["actor_token", "actor-token"], ["actor_token_type", ACCESS],
      ["resource", "https://api.example.com/a"], ["resource", "https://api.example.com/b"],
      ["audience", "api"], ["audience", "worker"]
    ]
    post "/token", URI.encode_www_form(params), "CONTENT_TYPE" => "application/x-www-form-urlencoded"
    assert_equal 200, last_response.status, last_response.body
    assert_equal "read", body["scope"]
    assert_operator body["expires_in"], :<=, 600
    token = body["access_token"]
    post "/introspect", token: token
    assert_equal true, body["active"]
    assert_equal "1", body["sub"]
    assert_equal({"sub" => "2"}, body["act"])
    assert_equal %w[https://api.example.com/a https://api.example.com/b api worker], body["aud"]
    exchange(subject_token: token)
    assert_equal 200, last_response.status
    post "/introspect", token: body["access_token"]
    assert_equal({"sub" => "2"}, body["act"])
    assert_equal %w[https://api.example.com/a https://api.example.com/b api worker], body["aud"]
  end

  def test_new_actor_wraps_subject_actor_history
    enable_policy
    seed_token("actor-token", account_id: 2)
    exchange(actor_token: "actor-token", actor_token_type: ACCESS)
    first_token = body.fetch("access_token")
    exchange(subject_token: first_token, actor_token: "subject-token", actor_token_type: ACCESS)
    assert_equal 200, last_response.status
    post "/introspect", token: body["access_token"]
    assert_equal({"sub" => "1", "act" => {"sub" => "2"}}, body["act"])
  end

  def test_reexchange_cannot_broaden_targets
    enable_policy
    exchange(resource: "https://api.example.com/a")
    token = body.fetch("access_token")
    exchange(subject_token: token, resource: "https://api.example.com/b")
    assert_error "invalid_target"
  end

  def test_reexchange_cannot_add_targets_via_the_other_parameter
    enable_policy
    exchange(resource: "https://api.example.com/a")
    token = body.fetch("access_token")
    exchange(subject_token: token, audience: "worker")
    assert_error "invalid_target"
    exchange(audience: "api")
    token = body.fetch("access_token")
    exchange(subject_token: token, resource: "https://api.example.com/a")
    assert_error "invalid_target"
  end

  def test_actor_validation_and_scope_restriction
    enable_policy
    exchange(actor_token: "unknown", actor_token_type: ACCESS)
    assert_error "invalid_request"
    seed_token("actor-token", account_id: 2, scopes: "read")
    exchange(actor_token: "actor-token", actor_token_type: ACCESS, scope: "write")
    assert_error "invalid_scope"
  end

  def test_expired_and_revoked_actors_are_rejected
    enable_policy
    id = seed_token("actor-token", account_id: 2, expires_in: Time.now - 1)
    exchange(actor_token: "actor-token", actor_token_type: ACCESS)
    assert_error "invalid_request"
    db[:oauth_grants].where(id: id).update(expires_in: Time.now + 600, revoked_at: Time.now)
    exchange(actor_token: "actor-token", actor_token_type: ACCESS)
    assert_error "invalid_request"
  end

  def test_disjoint_subject_and_actor_targets_do_not_become_unrestricted
    enable_policy
    exchange(resource: "https://api.example.com/a")
    subject = body.fetch("access_token")
    exchange(resource: "https://api.example.com/b")
    actor = body.fetch("access_token")
    exchange(subject_token: subject, actor_token: actor, actor_token_type: ACCESS)
    assert_error "invalid_target"
  end

  def test_subject_and_actor_targets_are_intersected
    enable_policy
    seed_token("bounded-subject", token_exchange_context: JSON.generate(
      "sub" => "1", "resource" => %w[https://api.example.com/a https://api.example.com/b]
    ))
    seed_token("bounded-actor", account_id: 2, token_exchange_context: JSON.generate(
      "sub" => "2", "resource" => ["https://api.example.com/b"]
    ))
    exchange(subject_token: "bounded-subject", actor_token: "bounded-actor", actor_token_type: ACCESS)
    assert_equal 200, last_response.status, last_response.body
    post "/introspect", token: body.fetch("access_token")
    assert_equal ["https://api.example.com/b"], body["aud"]
    assert_equal({"sub" => "2"}, body["act"])
  end

  def test_cross_client_exchange_retains_subject
    enable_policy
    basic_authorize "other", "secret"
    exchange
    assert_equal 200, last_response.status
    grant = db[:oauth_grants][token: hash_token(body["access_token"])]
    assert_equal 2, grant[:oauth_application_id]
    assert_equal 1, grant[:account_id]
  end

  def test_reuse_does_not_reuse_or_overwrite_source
    build_app { oauth_reuse_access_token true }
    basic_authorize "client", "secret"
    source = db[:oauth_grants][id: @source_id]
    exchange
    first = body.fetch("access_token")
    exchange
    refute_equal first, body["access_token"]
    assert_equal source, db[:oauth_grants][id: @source_id]
    assert_equal 3, db[:oauth_grants].count
  end
end
