# frozen_string_literal: true

require "rubygems/package"
require "tmpdir"
require "fileutils"
require "rbconfig"

package = Gem::Package.new(ARGV.fetch(0))
required = %w[lib/rodauth/token_exchange.rb lib/rodauth/token_exchange/version.rb
              lib/rodauth/token_exchange/client_authentication.rb
              lib/rodauth/features/oauth_token_exchange.rb README.md LICENSE
              CHANGELOG.md examples/migrate/001_token_exchange_context.rb
              examples/nginx-token-exchange.conf]
missing = required - package.spec.files
abort "Missing packaged files: #{missing.join(', ')}" unless missing.empty?

Dir.mktmpdir("token-exchange-package-") do |directory|
  package.extract_files(directory)
  $LOAD_PATH.unshift(File.join(directory, "lib"))
  require "rodauth/token_exchange"
  abort "Feature not registered" unless Rodauth::FEATURES[:oauth_token_exchange]
  abort "Loaded source checkout instead of package" unless $LOADED_FEATURES.include?(File.join(directory, "lib/rodauth/token_exchange.rb"))
  puts "Package #{package.spec.full_name}: contents and standalone loading verified"

  if ARGV.include?("--test")
    FileUtils.cp_r(File.expand_path("../test", __dir__), directory)
    activations = Gem.loaded_specs.values.reject { |spec| [package.spec.name, "bundler"].include?(spec.name) }.map do |spec|
      "gem #{spec.name.inspect}, #{("= " + spec.version.to_s).inspect}"
    end
    runner = <<~RUBY
      #{activations.join("\n")}
      require "rodauth/token_exchange"
      expected = File.expand_path("lib/rodauth/token_exchange.rb")
      abort "Loaded source checkout instead of package" unless $LOADED_FEATURES.include?(expected)
      Dir["test/**/*_test.rb"].sort.each { |path| require File.expand_path(path) }
      loaded = $LOADED_FEATURES.select { |path| path.match?(%r{/lib/rodauth/(?:token_exchange(?:/|\\.rb)|features/oauth_token_exchange\\.rb)}) }
      abort "Mixed package and checkout sources" unless loaded.all? { |path| path.start_with?(File.expand_path("lib") + "/") }
    RUBY
    # Bundler evaluates this checkout's gemspec (and version.rb) before -I is
    # applied. Use the same installed gems without its source-path injection.
    environment = ENV.keys.grep(/\ABUNDLE/).to_h { |name| [name, nil] }
    environment.merge!("RUBYOPT" => nil, "RUBYLIB" => nil, "RUBYGEMS_GEMDEPS" => nil,
                       "GEM_HOME" => Gem.dir, "GEM_PATH" => Gem.path.join(File::PATH_SEPARATOR))
    passed = system(environment, RbConfig.ruby, "-I#{directory}/lib", "-I#{directory}/test", "-e", runner, chdir: directory)
    abort "Packaged regression suite failed" unless passed
    puts "Package #{package.spec.full_name}: full regression suite verified against extracted artifact"
  end
end
