# Changelog

## 0.1.0 (2026-10-05)

Initial release.

- Add the RFC 8693 token-exchange grant to the rodauth-oauth token endpoint, accepting and issuing access tokens.
- Issue independent access tokens; source grants are neither replaced nor revoked.
- Bound scopes to the intersection of the subject token, actor token and client, and lifetime to an absolute deadline no later than either input's expiration, shared by the database and JWT `exp`.
- Support delegation: actor tokens, nested `act` history up to 16 entries, `act.iss` for actors with an issuer, and actors named by the subject's `may_act` claim.
- Support repeated `resource` and `audience` targets, inherited from inputs and never broadened.
- Render `sub` and local `act.sub` per the receiving client's OIDC subject type (public/pairwise).
- Provide policy hooks for exchange authorization and targets, and a resolver hook for trusted custom input tokens.
- Reject inputs whose local subject or actor account is no longer available.
- Require HTTPS and bound form size, parameter count and encoding for token-exchange requests.
- Preserve subject, actor and target claims in introspection and JWT output.
- Enforce resource origins and path boundaries for opaque and JWT access tokens when composed with `oauth_resource_indicators`, without changing the upstream gem or other auth classes.
- Store exchange context as JSON in a configurable grants column; include an example Sequel migration and nginx reference configuration.
