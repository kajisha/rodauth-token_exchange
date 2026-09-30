# frozen_string_literal: true

require_relative "test_helper"

class AccountValidationTest < ExchangeTest
  def test_deleted_subject_account_cannot_be_exchanged
    db[:accounts].where(id: 1).delete
    count = db[:oauth_grants].count
    exchange
    assert_error "invalid_request"
    assert_equal count, db[:oauth_grants].count
  end

  def test_deleted_actor_account_cannot_be_used_for_delegation
    build_app { oauth_token_exchange_authorized? { |_subject, _actor| true } }
    basic_authorize "client", "secret"
    seed_token("actor-token", account_id: 2)
    db[:accounts].where(id: 2).delete
    count = db[:oauth_grants].count
    exchange(actor_token: "actor-token", actor_token_type: ACCESS)
    assert_error "invalid_request"
    assert_equal count, db[:oauth_grants].count
  end

  def test_oauth_account_availability_policy_is_respected
    build_app do
      oauth_account_ds { |id| super(id).where(status_id: account_open_status_value) }
    end
    basic_authorize "client", "secret"
    exchange
    assert_equal 200, last_response.status, last_response.body
    db[:accounts].where(id: 1).update(status_id: 3)
    count = db[:oauth_grants].count
    exchange
    assert_error "invalid_request"
    assert_equal count, db[:oauth_grants].count
  end
end
