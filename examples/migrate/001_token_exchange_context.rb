# frozen_string_literal: true

require "sequel"
require "sequel/extensions/migration"

# Apply after the application's rodauth-oauth grants migration.
# Adjust the table/column name to match your Rodauth configuration.
# Separately remove any application-specific unique index that limits grants
# to one per account/client (possibly including scopes). Keep token uniqueness.
Sequel.migration do
  change do
    alter_table(:oauth_grants) do
      add_column :token_exchange_context, String, text: true
    end
  end
end
