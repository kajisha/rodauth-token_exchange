# frozen_string_literal: true

require "minitest/autorun"
require "rack/test"
require "sequel"
require "roda"
require "rodauth/oauth"
require "json"
require "digest"
require "base64"
require "rodauth/token_exchange"

class ExchangeTest < Minitest::Test
  include Rack::Test::Methods

  GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
  ACCESS = "urn:ietf:params:oauth:token-type:access_token"

  attr_reader :app, :db

  def setup
    @db = Sequel.sqlite
    @db.create_table(:accounts) do
      primary_key :id
      String :email
      Integer :status_id, default: 2
    end
    @db.create_table(:oauth_applications) do
      primary_key :id
      String :name
      String :client_id
      String :client_secret
      String :scopes
      String :grant_types
      String :token_endpoint_auth_method
    end
    @db.create_table(:oauth_grants) do
      primary_key :id
      Integer :account_id
      Integer :oauth_application_id
      String :type
      String :code
      String :token, unique: true
      String :refresh_token, unique: true
      String :scopes
      String :redirect_uri
      DateTime :expires_in
      DateTime :revoked_at
      String :token_exchange_context, text: true
    end
    @db[:accounts].insert(id: 1, email: "subject@example.com")
    @db[:accounts].insert(id: 2, email: "actor@example.com")
    @db[:oauth_applications].insert(id: 1, name: "client", client_id: "client", client_secret: "secret", scopes: "read write")
    @db[:oauth_applications].insert(id: 2, name: "other", client_id: "other", client_secret: "secret", scopes: "read write")
    @source_id = seed_token("subject-token")
    build_app
    basic_authorize "client", "secret"
  end

  def teardown
    @db.disconnect
  end

  def seed_token(token, **attributes)
    @db[:oauth_grants].insert({
      account_id: 1, oauth_application_id: 1, type: "authorization_code",
      token: hash_token(token), scopes: "read write", expires_in: Time.now + 1800
    }.merge(attributes))
  end

  def hash_token(token)
    Base64.urlsafe_encode64(Digest::SHA256.digest(token))
  end

  def build_app(*features, &configuration)
    database = @db
    @app = Class.new(Roda)
    @app.plugin :json_parser, content_type_regexp: /\Aapplication\/json\b/i
    @app.plugin :rodauth, json: :only do
      db database
      require_bcrypt? false
      enable :oauth_client_credentials_grant, :oauth_token_introspection, *features, :oauth_token_exchange
      oauth_applications_client_secret_hash_column nil
      oauth_application_scopes %w[read write]
      instance_exec(&configuration) if configuration
    end
    @app.route do |r|
      r.rodauth
      rodauth.load_oauth_server_metadata_route
      r.get "protected" do
        rodauth.require_oauth_authorization("read")
        rodauth.oauth_token_subject.to_s
      end
    end
    @_rack_test_sessions = {}
    @_rack_test_current_session = nil
    env "rack.url_scheme", "https"
  end

  def exchange(overrides = {})
    post "/token", {grant_type: GRANT, subject_token: "subject-token", subject_token_type: ACCESS}.merge(overrides)
  end

  def body
    JSON.parse(last_response.body)
  end

  def assert_error(error, status = 400)
    assert_equal status, last_response.status, last_response.body
    assert_equal error, body["error"], last_response.body
  end
end
