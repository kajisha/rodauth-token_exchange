# frozen_string_literal: true

require_relative "test_helper"

class RequestParametersTest < ExchangeTest
  def test_empty_optional_parameters_are_omitted
    %w[scope requested_token_type resource audience actor_token actor_token_type].each do |name|
      exchange(name => "")
      assert_equal 200, last_response.status, last_response.body
      assert_equal "read write", body["scope"]
    end
    exchange(actor_token: "", actor_token_type: "")
    assert_equal 200, last_response.status
  end

  def test_unknown_flat_names_do_not_change_known_parameters
    ["unknown=a&unknown[b]=c", "audience[]=ignored", "scope[nested]=ignored",
     "subject_token[nested]=ignored", "unknown=a&unknown=b"].each do |suffix|
      post_form(base_form + "&" + suffix)
      assert_equal 200, last_response.status, last_response.body
      assert_equal "read write", body["scope"]
    end
  end

  def test_duplicate_client_parameters_cannot_be_collapsed_by_rack
    header "Authorization", nil
    ["client_id=client&client_id=client&client_secret=secret",
     "client_id=client&client_secret=wrong&client_secret=secret",
     "client_id=client&client_secret=&client_secret=secret"].each do |credentials|
      post_form(base_form + "&" + credentials)
      assert_error "invalid_request"
    end
  end

  def test_client_credentials_in_query_are_rejected
    header "Authorization", nil
    post "/token?client_id=client&client_secret=secret", base_form,
         "CONTENT_TYPE" => "application/x-www-form-urlencoded"
    assert_error "invalid_request"
  end

  def test_empty_resources_are_omitted_with_native_resource_indicators
    db.alter_table(:oauth_grants) { add_column :resource, String }
    build_app(:oauth_resource_indicators) do
      oauth_token_exchange_targets_allowed? { |resources, _audiences, _subject, _actor| resources == ["https://api.example.com"] }
    end
    basic_authorize "client", "secret"
    post_form(base_form + "&resource=&resource=https%3A%2F%2Fapi.example.com")
    assert_equal 200, last_response.status, last_response.body
    grant = db[:oauth_grants][token: hash_token(body.fetch("access_token"))]
    assert_equal "https://api.example.com", grant[:resource]
  end

  private

  def base_form
    URI.encode_www_form(grant_type: GRANT, subject_token: "subject-token", subject_token_type: ACCESS)
  end

  def post_form(raw)
    post "/token", raw, "CONTENT_TYPE" => "application/x-www-form-urlencoded"
  end
end
