# frozen_string_literal: true

# Compatibility entry point; these checks are now part of the regression suite.
# bundle exec ruby -Ilib:test script/check_basic_auth_conformance.rb
require_relative "../test/client_authentication_test"
