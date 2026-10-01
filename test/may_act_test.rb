# frozen_string_literal: true

require_relative "test_helper"

class MayActTest < ExchangeTest
  IDP = "https://idp.example.com"
  EXTERNAL = "urn:example:external"

  def setup
    super
    seed_token("actor-token", account_id: 2)
  end

  def build_resolver_app(may_act:, actor: {subject: "agent", issuer: IDP}, subject_issuer: nil)
    build_app do
      oauth_token_exchange_resolve_token do |token, type|
        if type == EXTERNAL && token == "delegating"
          {subject: "1", issuer: subject_issuer, account_id: 1, application_id: 1, scopes: %w[read],
           expires_at: Time.now.to_i + 300, may_act: may_act}.compact
        elsif type == EXTERNAL && token == "agent"
          {subject: actor[:subject], issuer: actor[:issuer], account_id: nil, application_id: nil,
           scopes: %w[read], expires_at: Time.now.to_i + 300}
        else
          super(token, type)
        end
      end
    end
    basic_authorize "client", "secret"
  end

  def delegate(subject_token = "delegating", actor_token = "agent", actor_type = EXTERNAL)
    exchange(subject_token: subject_token, subject_token_type: EXTERNAL,
             actor_token: actor_token, actor_token_type: actor_type)
  end

  def test_default_policy_accepts_actor_named_by_may_act_with_issuer
    build_resolver_app(may_act: {"sub" => "agent", "iss" => IDP})
    delegate
    assert_equal 200, last_response.status, last_response.body
    post "/introspect", token: body.fetch("access_token")
    assert_equal "1", body["sub"]
    assert_equal({"sub" => "agent", "iss" => IDP}, body["act"])
    refute body.key?("may_act")
  end

  def test_default_policy_rejects_actors_not_named_by_may_act
    [{"sub" => "someone-else"}, {"sub" => "agent", "iss" => "https://other.example.com"},
     {"sub" => "agent", "email" => "agent@example.com"}, {}].each do |may_act|
      build_resolver_app(may_act: may_act)
      delegate
      assert_error "invalid_request"
    end
  end

  def test_may_act_without_issuer_matches_subject_only
    build_resolver_app(may_act: {"sub" => "agent"}, actor: {subject: "agent", issuer: nil})
    delegate
    assert_equal 200, last_response.status, last_response.body
    post "/introspect", token: body.fetch("access_token")
    assert_equal({"sub" => "agent"}, body["act"])
  end

  def test_may_act_without_issuer_rejects_actor_from_another_issuer
    build_resolver_app(may_act: {"sub" => "agent"})
    delegate
    assert_error "invalid_request"
  end

  def test_may_act_without_issuer_uses_the_subject_issuer
    build_resolver_app(may_act: {"sub" => "agent"}, subject_issuer: IDP)
    delegate
    assert_equal 200, last_response.status, last_response.body
    build_resolver_app(may_act: {"sub" => "2"}, subject_issuer: IDP)
    delegate("delegating", "actor-token", ACCESS)
    assert_error "invalid_request"
  end

  def test_preserved_may_act_keeps_the_subject_issuer
    build_resolver_app(may_act: {sub: "2"}, subject_issuer: IDP)
    exchange(subject_token: "delegating", subject_token_type: EXTERNAL)
    assert_equal 200, last_response.status, last_response.body
    token = body.fetch("access_token")
    grant = db[:oauth_grants][token: hash_token(token)]
    assert_equal({"sub" => "2", "iss" => IDP}, JSON.parse(grant[:token_exchange_context])["may_act"])
    exchange(subject_token: token, actor_token: "actor-token", actor_token_type: ACCESS)
    assert_error "invalid_request"
  end

  def test_actor_without_may_act_remains_rejected_by_default
    exchange(actor_token: "actor-token", actor_token_type: ACCESS)
    assert_error "invalid_request"
  end

  def test_may_act_requires_the_subject_token_client
    build_resolver_app(may_act: {"sub" => "agent", "iss" => IDP})
    basic_authorize "other", "secret"
    delegate
    assert_error "invalid_request"
  end

  def test_may_act_is_preserved_until_an_actor_is_added
    build_resolver_app(may_act: {"sub" => "2"})
    exchange(subject_token: "delegating", subject_token_type: EXTERNAL)
    assert_equal 200, last_response.status, last_response.body
    token = body.fetch("access_token")
    grant = db[:oauth_grants][token: hash_token(token)]
    assert_equal({"sub" => "2"}, JSON.parse(grant[:token_exchange_context])["may_act"])
    exchange(subject_token: token, actor_token: "actor-token", actor_token_type: ACCESS)
    assert_equal 200, last_response.status, last_response.body
    delegated = body.fetch("access_token")
    grant = db[:oauth_grants][token: hash_token(delegated)]
    refute JSON.parse(grant[:token_exchange_context]).key?("may_act")
    exchange(subject_token: delegated, actor_token: "actor-token", actor_token_type: ACCESS)
    assert_error "invalid_request"
  end

  def test_invalid_issuer_or_may_act_types_are_rejected
    [{issuer: ""}, {issuer: 1}].each do |actor|
      build_resolver_app(may_act: {"sub" => "agent"}, actor: {subject: "agent"}.merge(actor))
      delegate
      assert_error "invalid_request"
    end
    build_resolver_app(may_act: "agent")
    delegate
    assert_error "invalid_request"
  end
end
