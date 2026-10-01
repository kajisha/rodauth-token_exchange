# frozen_string_literal: true

require_relative "test_helper"

class TransportTest < ExchangeTest
  def test_plain_http_cannot_issue_tokens
    env "rack.url_scheme", "http"
    count = db[:oauth_grants].count
    exchange
    assert_error "invalid_request"
    assert_equal count, db[:oauth_grants].count
  end

  def test_untrusted_forwarded_headers_cannot_bypass_transport_check
    env "rack.url_scheme", "http"
    header "X-Forwarded-Proto", "https"
    header "Forwarded", "proto=https"
    exchange
    assert_error "invalid_request"
  end

  def test_plain_http_exchange_is_rejected_before_client_authentication
    env "rack.url_scheme", "http"
    basic_authorize "client", "wrong"
    exchange
    assert_error "invalid_request"
  end

  def test_other_grants_and_endpoints_keep_upstream_transport_behavior
    env "rack.url_scheme", "http"
    post "/token", grant_type: "client_credentials"
    assert_equal 200, last_response.status, last_response.body
    post "/introspect", token: "subject-token"
    assert_equal 200, last_response.status, last_response.body
    assert_equal true, body["active"]
  end

  def test_https_can_issue_tokens
    env "rack.url_scheme", "https"
    exchange
    assert_equal 200, last_response.status, last_response.body
  end
end
