# frozen_string_literal: true

# Uses the same real Rack/Rodauth/SQLite fixture as the regression tests.
# N=1000 ROUNDS=5 OUTPUT=benchmark.json bundle exec ruby -Ilib script/benchmark_token_exchange.rb
require_relative "../test/test_helper"
require "jwt"

class TokenExchangeBenchmark < ExchangeTest
  def test_benchmark
    iterations = Integer(ENV.fetch("N", "1000"))
    rounds = Integer(ENV.fetch("ROUNDS", "5"))
    results = {}
    %w[opaque delegated jwt many_targets].each do |scenario|
      samples = []
      rounds.times do
        teardown
        setup
        configure_scenario(scenario)
        100.times { perform_request }
        GC.start
        allocated = GC.stat(:total_allocated_objects)
        elapsed = []
        iterations.times do
          started = monotonic
          perform_request
          elapsed << (monotonic - started) * 1000
        end
        objects = GC.stat(:total_allocated_objects) - allocated
        assert_equal 200, last_response.status, last_response.body
        sorted = elapsed.sort
        samples << {mean_ms: elapsed.sum / iterations, p50_ms: sorted[iterations / 2],
                    p95_ms: sorted[(iterations * 0.95).floor], objects_per_request: objects.fdiv(iterations)}
      end
      queries = []
      logger = Object.new
      logger.define_singleton_method(:info) { |sql| queries << sql }
      db.loggers << logger
      perform_request
      db.loggers.delete(logger)
      grant_query = queries.find { |sql| sql.include?("SELECT * FROM `oauth_grants`") }.sub(/\A\([^)]*\) /, "")
      query_plan = db.fetch("EXPLAIN QUERY PLAN #{grant_query}").all

      profile = Hash.new { |hash, key| hash[key] = {calls: 0, ms: 0.0} }
      profiler = Module.new
      %i[create_token oauth_token_exchange_parameters oauth_token_exchange_stored_grant generate_token].each do |name|
        profiler.define_method(name) do |*args|
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          super(*args)
        ensure
          stats = profile[name]
          stats[:calls] += 1
          stats[:ms] += (Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000
        end
      end
      app.rodauth.prepend(profiler)
      50.times { perform_request }
      results[scenario] = {samples: samples, sql_per_request: queries.size,
                           sql_statements: queries.map { |sql| sql.sub(/\A\([^)]*\) /, "").split.first }.tally,
                           token_lookup_plan: query_plan,
                           inclusive_profile: profile.sort_by { |_, stats| -stats[:ms] }.to_h}
      means = samples.map { |sample| sample[:mean_ms] }.sort
      puts "#{scenario}: median mean #{means[rounds / 2].round(3)} ms/request, " \
           "#{samples.map { |sample| sample[:objects_per_request] }.sum.fdiv(rounds).round} objects/request, #{queries.size} SQL statements/request"
    end
    if ENV["OUTPUT"]
      File.write(ENV["OUTPUT"], JSON.pretty_generate(ruby: RUBY_DESCRIPTION, iterations: iterations, rounds: rounds, results: results))
    end
  end

  private

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def configure_scenario(scenario)
    build_app(*(scenario == "jwt" ? [:oauth_jwt] : [])) do
      oauth_jwt_keys("HS256" => "benchmark-signing-key-" * 4) if scenario == "jwt"
      oauth_token_exchange_authorized? { |_subject, _actor| true }
      oauth_token_exchange_targets_allowed? { |_resources, _audiences, _subject, _actor| true }
    end
    basic_authorize "client", "secret"
    params = {grant_type: GRANT, subject_token: "subject-token", subject_token_type: ACCESS, scope: "read"}.to_a
    if scenario == "delegated"
      seed_token("actor-token", account_id: 2)
      params.concat([[:actor_token, "actor-token"], [:actor_token_type, ACCESS]])
    elsif scenario == "many_targets"
      100.times { |index| params << [:resource, "https://api.example.com/#{index}"] }
    end
    @encoded_request = URI.encode_www_form(params)
  end

  def perform_request
    post "/token", @encoded_request, "CONTENT_TYPE" => "application/x-www-form-urlencoded"
    raise last_response.body unless last_response.status == 200
  end
end
