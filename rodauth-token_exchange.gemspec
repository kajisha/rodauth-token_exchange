# frozen_string_literal: true

require_relative "lib/rodauth/token_exchange/version"

Gem::Specification.new do |spec|
  spec.name = "rodauth-token_exchange"
  spec.version = Rodauth::TokenExchange::VERSION
  spec.summary = "RFC 8693 Token Exchange for rodauth-oauth"
  spec.authors = ["Hiroshi Kajisha"]
  spec.email = ["1960696+kajisha@users.noreply.github.com"]
  spec.license = "MIT"
  spec.homepage = "https://github.com/kajisha/rodauth-token_exchange"
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"
  spec.required_ruby_version = ">= 3.0"
  spec.files = Dir["lib/**/*.rb", "examples/**/*.rb", "examples/**/*.conf", "README.md", "LICENSE", "CHANGELOG.md"]
  spec.require_paths = ["lib"]
  spec.add_dependency "rodauth-oauth", "~> 1.7.0"
end
