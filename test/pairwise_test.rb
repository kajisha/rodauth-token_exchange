# frozen_string_literal: true

require_relative "test_helper"
require "jwt"

class PairwiseTest < ExchangeTest
  KEY = "pairwise-test-signing-key-" * 3
  SECRET = "pairwise-salt"

  def setup
    super
    db.alter_table(:oauth_applications) do
      add_column :redirect_uri, String
      add_column :subject_type, String
      add_column :sector_identifier_uri, String
    end
    db[:oauth_applications].where(id: 1).update(redirect_uri: "https://client.example.com/cb", subject_type: "pairwise")
    db[:oauth_applications].where(id: 2).update(redirect_uri: "https://other.example.com/cb", subject_type: "public")
    seed_token("actor-token", account_id: 2)
    build_app(:oidc) do
      hmac_secret "pairwise-test-hmac-secret"
      oauth_jwt_keys("HS256" => KEY)
      oauth_jwt_subject_secret SECRET
      oauth_token_exchange_authorized? { |_subject, _actor| true }
    end
    basic_authorize "client", "secret"
  end

  def pairwise(host, account)
    Digest::SHA256.hexdigest([host, account, SECRET].join)
  end

  def claims
    JWT.decode(body.fetch("access_token"), KEY, true, algorithms: ["HS256"]).first
  end

  def test_pairwise_client_receives_its_sector_identifiers
    exchange(actor_token: "actor-token", actor_token_type: ACCESS)
    assert_equal 200, last_response.status, last_response.body
    token = claims
    assert_equal pairwise("client.example.com", 1), token["sub"]
    assert_equal({"sub" => pairwise("client.example.com", 2)}, token["act"])
    post "/introspect", token: body.fetch("access_token")
    assert_equal pairwise("client.example.com", 1), body["sub"]
    assert_equal({"sub" => pairwise("client.example.com", 2)}, body["act"])
  end

  def test_public_client_receives_public_identifiers_from_pairwise_exchange_output
    exchange(actor_token: "actor-token", actor_token_type: ACCESS)
    first = body.fetch("access_token")
    grant = db[:oauth_grants][token: hash_token(first)]
    assert_equal "1", JSON.parse(grant[:token_exchange_context])["sub"]
    basic_authorize "other", "secret"
    exchange(subject_token: first)
    assert_equal 200, last_response.status, last_response.body
    assert_equal "1", claims["sub"]
    assert_equal({"sub" => "2"}, claims["act"])
  end

  def test_nested_local_actors_are_rendered_per_depth
    exchange(actor_token: "actor-token", actor_token_type: ACCESS)
    first = body.fetch("access_token")
    exchange(subject_token: first, actor_token: "subject-token", actor_token_type: ACCESS)
    assert_equal 200, last_response.status, last_response.body
    assert_equal({"sub" => pairwise("client.example.com", 1),
                  "act" => {"sub" => pairwise("client.example.com", 2)}}, claims["act"])
  end

  def test_client_subjects_are_not_pairwise
    db[:oauth_grants].where(id: @source_id).update(account_id: nil)
    exchange
    assert_equal 200, last_response.status, last_response.body
    assert_equal "client", claims["sub"]
  end
end
