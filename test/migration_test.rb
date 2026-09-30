# frozen_string_literal: true

require "minitest/autorun"
require "sequel"
require "sequel/extensions/migration"

class MigrationTest < Minitest::Test
  def test_example_migration_is_reversible
    database = Sequel.sqlite
    database.create_table(:oauth_grants) { primary_key :id }
    database[:oauth_grants].insert
    directory = File.expand_path("../examples/migrate", __dir__)
    Sequel::Migrator.run(database, directory)
    assert_includes database.schema(:oauth_grants).map(&:first), :token_exchange_context
    assert_nil database[:oauth_grants].first[:token_exchange_context]
    Sequel::Migrator.run(database, directory, target: 0)
    refute_includes database.schema(:oauth_grants).map(&:first), :token_exchange_context
    assert_equal 1, database[:oauth_grants].count
  ensure
    database&.disconnect
  end
end
