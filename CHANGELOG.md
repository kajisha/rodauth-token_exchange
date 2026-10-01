# Changelog

## 0.1.0 (unreleased)

- Accept actors named by the subject's `may_act` claim in the default authorization policy. A `may_act` without `iss` matches only actors from the subject's issuer.
- Emit `act.iss` for actor identities that carry an issuer.
- Render `sub` and local `act.sub` per the receiving client's OIDC subject type (public/pairwise).
- Limit the HTTPS requirement to token-exchange requests.
- Apply the extension's form byte, parameter-count and encoding limits only to token-exchange requests.

- Reject exchange inputs whose local subject or actor account is no longer available.

- Pin database and JWT expiration to an absolute input-bounded deadline.
- Reject actor chains exceeding 16 entries with an OAuth error.
- Bound flat form parsing by bytes and parameter count, retaining configured Rack limits.
- Add non-exchange client authentication regression coverage.

- Add the RFC 8693 token-exchange grant as a rodauth-oauth extension.
- Issue independent access tokens with bounded scopes and lifetime; preserve source grants.
- Support subject/actor policy hooks, repeated resource/audience targets, and trusted custom token resolvers.
- Preserve subject, actor history, and target claims in introspection and JWT output.
- Store exchange context as JSON in a configurable grants column.
- Include endpoint tests and an example Sequel migration.
