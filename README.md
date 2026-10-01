# rodauth-token_exchange

An extension gem for [rodauth-oauth](https://github.com/HoneyryderChuck/rodauth-oauth) that adds the [RFC 8693 OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693.html) grant to the token endpoint.

Requires Ruby 3.0 or newer and rodauth-oauth `~> 1.7.0`.

## Installation

For a published release, add to your Gemfile and run `bundle install`:

```ruby
gem "rodauth-token_exchange", "~> 0.1.0"
```

Until the first release is published, or when developing against a local checkout,
use this entry instead:

```ruby
gem "rodauth-token_exchange", path: "/path/to/rodauth-token_exchange"
```

In your existing Rodauth OAuth server, load the extension and enable it **after** other OAuth features, including `oauth_jwt`, `oauth_token_introspection`, and `oauth_resource_indicators` when used:

```ruby
require "rodauth/token_exchange"

# Inside your existing Rodauth configuration:
enable :oauth_token_introspection
enable :oauth_token_exchange
```

Keep the existing OAuth database, application registration, client authentication, and signing-key configuration. If an application's `grant_types` is restricted, allow `urn:ietf:params:oauth:grant-type:token-exchange` for that application. The server advertises this grant in its supported grant types.

Enable `oauth_pkce` and `oauth_device_code_grant` before `oauth_token_exchange`
when composing these features; unsafe ordering raises `Rodauth::ConfigurationError`.
Features using `oauth_assertion_base`, including `oauth_jwt_bearer_grant`, cannot
currently be combined with this extension and are rejected at configuration time
regardless of ordering. Upstream assertion dispatch treats the token-exchange URN
as an assertion grant. This limitation does not affect JWT access-token output
through `oauth_jwt`, which is supported and tested.

Add a nullable text column named `token_exchange_context` to the grants table; it stores JSON containing subject, actor, and target context. A Sequel migration is provided in [examples/migrate/001_token_exchange_context.rb](examples/migrate/001_token_exchange_context.rb). The column name is configurable with `oauth_grants_token_exchange_context_column`.

The grants table must allow **multiple grants for the same account and client**. Remove any unique index enforcing one grant per account/client (including variants containing scopes), using your application's actual index name. Keep token and refresh-token uniqueness constraints. Exchanges always insert a new grant and bypass access-token reuse; other grant types retain their existing behavior. The example migration does not guess or remove application-specific indexes.

## Exchange an access token

Send form-encoded parameters to the existing token endpoint:

Use HTTPS for the token endpoint and every endpoint receiving tokens. The extension
rejects token-exchange requests, before client authentication, unless the server's
`rack.url_scheme` is `https`. Other grants and endpoints keep rodauth-oauth's
transport behavior. A TLS-terminating proxy must use trusted middleware to set that value;
untrusted `Forwarded` or `X-Forwarded-Proto` headers alone are not accepted. Do not
expose the backend directly or send credentials over HTTP before a redirect.

```sh
curl --user "$CLIENT_ID:$CLIENT_SECRET" \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode "subject_token=$ACCESS_TOKEN" \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  --data-urlencode 'scope=read' \
  https://auth.example.com/token
```

The response contains `access_token`, `issued_token_type`, `token_type`, `expires_in`, and `scope`. The issued token type is `urn:ietf:params:oauth:token-type:access_token`, including when `oauth_jwt` produces a JWT-formatted access token. No refresh token is issued. The source token is neither replaced nor revoked by exchange.

`requested_token_type` is optional and accepts only the access-token type above. `actor_token` and `actor_token_type` must be supplied together. Repeated bare `resource` and `audience` parameters are supported. OAuth names are flat: unknown names such as `resource[]` are ignored and never become arrays or overwrite recognized parameters. Empty values are treated as omitted; missing required parameters and duplicate recognized single-value parameters are rejected. Resource values must be absolute URIs without fragments. Exchange and client-authentication parameters belong in the form body, not the query string.

Basic authentication accepts case-insensitive scheme names and form-decodes the
client ID and secret once, as required by RFC 6749. Percent-encode each component
before constructing the Basic credential when it contains reserved characters.
Combining Basic authentication with a body secret or client assertion is rejected.

For token-exchange requests, form bodies and query strings are capped at 4 MiB
and 4,096 parameters. The body is read with a byte bound before authentication.
Limits enforced by Rack's configured flat parser also apply, including on
versions without a pair parser. Stricter Rack limits are preserved. Excess input
returns `invalid_request`. A body naming the token-exchange grant type in any
parameter or encoding is parsed as an exchange; other grants keep
rodauth-oauth's parsing and limits.

Password-authenticated endpoints also require brute-force protection (RFC 6749
§2.3.1). Configure and test an attempt limit at the deployment's trusted gateway
or authentication service, shared across workers and covering every endpoint
alias. The packaged [nginx reference configuration](examples/nginx-token-exchange.conf)
provides a worker-shared IP limit and verified TLS to the backend. Adapt its
placeholders, authority, certificates and network boundaries before deployment.
Enabling the feature alone does not install a limiter or prove deployment compliance.

## Defaults and policy

By default, only a token issued to the authenticated client can be exchanged, resource/audience targets are rejected, and actors are rejected unless the subject identity carries a `may_act` claim (RFC 8693 §4.4) naming that actor. Every `may_act` claim must equal the actor's `sub` or `iss`; any other claim never matches. A `may_act` without `iss` names a principal of the subject's issuer, so the actor's issuer must equal the subject's (both absent for local tokens). An exchange without an actor preserves `may_act`, together with that issuer, for later exchanges, and an exchange that adds an actor consumes it. `may_act` is stored for the authorization server only and is not emitted in JWT or introspection output. Policies can reuse the check through `oauth_token_exchange_may_act?(subject, actor)`. The default resolver accepts active, unexpired local database access tokens, including exchange-issued JWT access tokens whose token hash is stored locally. It rejects sender-bound inputs rather than converting them into bearer tokens. It does not accept arbitrary external JWTs, SAML assertions, refresh tokens, or the `urn:ietf:params:oauth:token-type:jwt` type.

For account-backed inputs, the default resolver also requires the account to be
available through Rodauth's `oauth_account_ds`. Deleted accounts and accounts
excluded by that dataset are rejected for both subject and actor tokens. The
default dataset checks existence; applications can filter closed or disabled
accounts through that existing hook. Client subjects with no account remain supported.

Scopes are limited to the intersection of the subject token, authenticated application's allowed scopes, and actor token when present. Omitting `scope` selects that intersection; an empty intersection or explicitly requesting anything broader returns `invalid_scope`. Lifetime cannot exceed the configured access-token lifetime or the remaining lifetime of either input token.

Exchange expiration is fixed as an absolute deadline before issuance. Database
expiration and JWT `exp` share that deadline, so processing delays cannot extend
the lifetime. Inputs that expire before storage cause `invalid_request`.

Override these Rodauth configuration hooks to implement your application's trust policy:

```ruby
oauth_token_exchange_authorized? do |subject, actor|
  # Example: retain same-client, actor-free authorization.
  actor.nil? && subject[:application_id] ==
    oauth_application[oauth_applications_id_column]
end

oauth_token_exchange_targets_allowed? do |resources, audiences, subject, actor|
  # Example: permit only this API, with no named audience or delegation.
  actor.nil? && audiences.empty? &&
    resources == ["https://api.example.com"] &&
    subject[:application_id] == oauth_application[oauth_applications_id_column]
end
```

For delegation or cross-client exchange, the authorization hook must check which authenticated client may act for the subject and actor. Possession of two tokens alone is not sufficient authorization. Avoid unconditional `true` policies.

Targets already attached to subject or actor tokens are inherited when omitted and cannot be broadened on subsequent exchanges, even by an approving target policy. Incompatible target restrictions fail with `invalid_target`. Native `oauth_resource_indicators` resource restrictions are preserved. Named audiences require an application-defined routing and authorization policy.

Introspection and JWT output preserve `sub`, `act`, and target `aud` claims. Adding an actor creates a new `act.sub` and nests the subject's previous actor history under `act.act`. Exchanging without a new actor preserves existing actor context. Resource servers must enforce the intended audience and current actor authorization as well as token validity; verifying a JWT signature alone is insufficient. Historical nested actors describe prior delegation and do not independently grant current authority.

An actor identity with an `issuer` produces `act.iss` alongside `act.sub`, distinguishing equal subjects from different issuers. An `act` entry without `iss` identifies a subject of this authorization server.

With the `oidc` feature, the issued token's `sub` and local actors' `act.sub` follow the subject type (`public` or `pairwise`) of the client receiving the token, matching rodauth-oauth's JWT access tokens. Pairwise identifiers use that client's sector. The exchange context stores public identifiers and recomputes them for each client, so a pairwise identifier never flows into another client's token. Client subjects and actors with an `iss` are emitted unchanged.

Actor history is limited to 16 nested actors. An exchange exceeding this bound
returns `invalid_request` without issuing a grant or truncating the history.

JWT exchange tokens include a private `token_exchange_id` claim used to produce a distinct `jti` for each grant. A separate rodauth-oauth resource server using upstream's `jti` verification should load and enable this extension too (after `oauth_jwt`, with `is_authorization_server? false`). Generic JWT consumers can treat `jti` as an opaque identifier. Introspection checks the stored exchange token's expiration and revocation; offline JWT consumers need their own revocation strategy. Revoking an input does not automatically revoke previously issued exchange tokens.

Errors use the existing OAuth JSON response format: `invalid_request` for malformed or invalid credentials and denied exchange policies, `invalid_target` for unacceptable targets, `invalid_scope` for scope escalation, and `unauthorized_client` when the client's allowed grant list excludes exchange. Existing client-authentication errors come from rodauth-oauth.

## Custom input token verification

Override `oauth_token_exchange_resolve_token(token, token_type)` to accept additional trusted inputs. Return `nil` for invalid or unsupported tokens, or a hash containing:

| Key | Meaning |
| --- | --- |
| `subject` | Nonempty verified subject string |
| `account_id` | Mapped local account ID, or `nil` for a client subject |
| `application_id` | Trusted local issuing application ID used by authorization policy |
| `scopes` | Array of authorized scope strings |
| `expires_at` | Expiration as an integer Unix timestamp |
| `resources` | Optional array of permitted resource URI strings |
| `audiences` | Optional array of permitted audience strings |
| `act` | Optional verified actor claim hash |
| `issuer` | Optional verified issuer string; emitted as `act.iss` when this identity is the actor |
| `may_act` | Optional verified RFC 8693 `may_act` hash naming who may act for this subject |

Call `super(token, token_type)` for input types handled by the built-in resolver. An external JWT or SAML resolver must verify signature, issuer, expiry, intended audience, and applicable client/key bindings before returning an identity. It must preserve target restrictions and verified actor context. Do not treat decoded claims as verified identity, silently drop sender constraints, or map an untrusted issuer's subject directly onto a local account.

## Development

Run these commands from a source checkout. The installed Gem includes runtime
code, example configurations and migration, README, changelog, and license;
development scripts and tests are distributed with the source checkout.
Development uses Bundler 2.4.22 and requires a C toolchain and Ruby development
headers to compile the SQLite test dependency for the Ruby version in use.

```sh
gem install bundler -v 2.4.22
bundle _2.4.22_ install
bundle exec rake
bundle exec ruby -Ilib script/verify_tls.rb
gem build rodauth-token_exchange.gemspec
bundle exec ruby script/verify_package.rb rodauth-token_exchange-0.1.0.gem --test
```

Tests exercise the extension through a Roda token endpoint with an SQLite database. They cover validation, policy, scope/lifetime restriction, delegation, introspection, JWT output, target inheritance, and independent grant storage. Database adapters and framework integrations beyond this test setup are not certified by this project.

Licensed under the [MIT License](LICENSE).
