# frozen_string_literal: true

require_relative "test_helper"
require "uri"

class ClientAuthenticationTest < ExchangeTest
  def test_basic_scheme_is_case_insensitive
    %w[basic BASIC bAsIc].each do |scheme|
      header "Authorization", "#{scheme} #{Base64.strict_encode64('client:secret')}"
      exchange
      assert_equal 200, last_response.status, last_response.body
    end
  end

  def test_basic_credentials_are_form_decoded_once
    ["client+id", "client:id", "client id", "client%2Bid", "日本語"].each do |client_id|
      secret = "secret:+ %日本語"
      db[:oauth_applications].where(id: 1).update(client_id: client_id, client_secret: secret)
      basic_authorize URI.encode_www_form_component(client_id), URI.encode_www_form_component(secret)
      exchange
      assert_equal 200, last_response.status, last_response.body
    end
  end

  def test_malformed_basic_credentials_are_rejected
    tokens = ["", "!!!!", Base64.strict_encode64("client"),
              Base64.strict_encode64("client:secret") + "!",
              Base64.strict_encode64("client:%ZZ"), Base64.strict_encode64("client:%FF")]
    tokens.each do |token|
      header "Authorization", "Basic #{token}"
      exchange
      assert_error "invalid_client", 401
    end
  end

  def test_invalid_basic_cannot_fall_back_to_valid_post_credentials
    header "Authorization", "basic !!!"
    exchange(client_id: "client", client_secret: "secret")
    assert_error "invalid_request"
  end

  def test_multiple_client_authentication_mechanisms_are_rejected
    [{client_id: "client", client_secret: "secret"},
     {client_assertion: "assertion", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}].each do |credentials|
      exchange(credentials)
      assert_error "invalid_request"
    end
  end

  def test_client_id_alone_is_not_a_second_authentication_mechanism
    exchange(client_id: "client")
    assert_equal 200, last_response.status, last_response.body
  end

  def test_empty_authentication_parameters_are_omitted
    exchange(client_secret: "", client_assertion: "")
    assert_equal 200, last_response.status, last_response.body
  end

  def test_registered_authentication_method_is_enforced
    db[:oauth_applications].where(id: 1).update(token_endpoint_auth_method: "client_secret_post")
    exchange
    assert_error "invalid_client", 401
  end

  def test_post_authentication_still_works_without_basic_header
    header "Authorization", nil
    exchange(client_id: "client", client_secret: "secret")
    assert_equal 200, last_response.status, last_response.body
  end

  def test_post_and_assertion_authentication_cannot_be_combined
    header "Authorization", nil
    exchange(client_id: "client", client_secret: "secret", client_assertion: "assertion",
             client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    assert_error "invalid_request"
  end

  def test_other_grant_parameters_cannot_bypass_client_authentication
    [[:oauth_pkce, :code_verifier], [:oauth_device_code_grant, :device_code]].each do |feature, parameter|
      build_app(feature)
      header "Authorization", nil
      exchange(client_id: "client", parameter => "attacker")
      assert_error "invalid_client", 401
      post "/token?#{parameter}=attacker", grant_type: GRANT, subject_token: "subject-token",
           subject_token_type: ACCESS, client_id: "client"
      assert_error "invalid_client", 401
    end
  end

  def test_explicit_public_client_authentication_remains_supported
    db[:oauth_applications].where(id: 1).update(token_endpoint_auth_method: "none")
    header "Authorization", nil
    exchange(client_id: "client")
    assert_equal 200, last_response.status, last_response.body
  end

  def test_client_credentials_grant_accepts_case_insensitive_basic_scheme
    %w[basic BASIC bAsIc].each do |scheme|
      header "Authorization", "#{scheme} #{Base64.strict_encode64('client:secret')}"
      post "/token", grant_type: "client_credentials", scope: "read"
      assert_equal 200, last_response.status, last_response.body
      refute_empty body.fetch("access_token")
    end
  end

  def test_client_credentials_grant_decodes_basic_credentials_once
    client_id = "client:+ %2B日本語"
    secret = "secret:+ %2B日本語"
    db[:oauth_applications].where(id: 1).update(client_id: client_id, client_secret: secret)
    basic_authorize URI.encode_www_form_component(client_id), URI.encode_www_form_component(secret)

    post "/token", grant_type: "client_credentials", scope: "read"

    assert_equal 200, last_response.status, last_response.body
    refute_empty body.fetch("access_token")
  end

  def test_client_credentials_grant_accepts_registered_post_authentication
    db[:oauth_applications].where(id: 1).update(token_endpoint_auth_method: "client_secret_post")
    header "Authorization", nil

    post "/token", grant_type: "client_credentials", scope: "read",
         client_id: "client", client_secret: "secret"

    assert_equal 200, last_response.status, last_response.body
    refute_empty body.fetch("access_token")
  end

  def test_client_credentials_grant_rejects_wrong_basic_secret
    basic_authorize "client", "wrong"

    post "/token", grant_type: "client_credentials", scope: "read"

    assert_error "invalid_client", 401
  end

  def test_client_credentials_grant_rejects_multiple_authentication_mechanisms
    post "/token", grant_type: "client_credentials", scope: "read",
         client_id: "client", client_secret: "secret"

    assert_error "invalid_request"
  end
end
