# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because the crate is still pre-1.0, breaking changes may land in any `0.x.y`
release per SemVer §4. They are called out explicitly in the **Changed**
and **Removed** sections.

## [Unreleased]

### Added

- `DeviceCodeCredentialOptions`, allowing callers to pass a custom HTTP
  `Pipeline` (for shared connection pooling, custom retry/transport/policy
  configuration) and an async `message_handler` callback for the device-code
  instruction message instead of the default `eprintln!` to stderr.
- `AzureauthCliCredentialOptions` with `modes` and `prompt_hint` fields,
  replacing the previously unreachable fluent builder methods on
  `AzureauthCliCredential`.
- `RefreshTokenResponse::expires_on()` and `DeviceCodeAuthorization::expires_on()`
  accessors that return an absolute `OffsetDateTime` anchored at deserialize
  time, so repeated reads of the same response don't drift forward with the
  wall clock.
- `DeviceCodeAuthorization::token_type()`, `scopes()`, and `expires_in()`
  accessors (in concert with the visibility tightening below).
- `start()` now parses `DeviceCodeErrorResponse` on phase-one failure and
  wraps it as the source of the returned error, matching what `stream()`
  already did on phase-two failures.
- `clippy::incompatible_msrv` is now enforced via `rust-version = "1.91"` in
  `Cargo.toml`; `cargo publish` will reject newer-stdlib calls.
- The polling interval is rejected at deserialize time if it falls outside
  `0..=i64::MAX` (negative values, JSON overflows) and clamped to a one-second
  minimum so an `interval: 0` from the server can't turn the polling loop
  into a tight loop on the AAD token endpoint.
- Significant test coverage: `Send` bounds on every public async constructor,
  `MockCredential`-driven chain semantics (success short-circuit, fallback,
  aggregated errors, sticky-credential behavior, `retry_sources` mode),
  `format_aggregate_error` source-chain walking, custom-pipeline honoring,
  message-handler async borrow path, scope-order independence in both caches,
  `expires_on()` stability, optional-field tolerance on
  `DeviceCodeErrorResponse`, polling-interval bounds, azureauth binary
  lookup caching, and options-struct plumbing through to the CLI.

### Changed

The crate is pre-1.0. Every entry in this section is a breaking API change
under SemVer §4.

- `DeviceCodeCredential::new`, `AzureauthCliCredential::new`,
  `DeviceCodeCredentialOptions`, and `AzureauthCliCredentialOptions` now
  follow the options-struct constructor pattern used across the rest of the
  crate (and aligned with upstream `azure_identity`'s option-bag credentials).
  Both options structs are `#[non_exhaustive]` so future fields stay
  non-breaking.
- `AzureauthCliCredential::new` returns `Arc<Self>` directly instead of
  `azure_core::Result<Arc<Self>>` (the operation was always infallible).
- `device_code::start` takes `&Pipeline` and `tenant_id: &str` (was
  `Pipeline` by value and `T: Into<Cow<'a, str>>`), and
  `DeviceCodePhaseOneResponse` lost its lifetime parameter.
- `DeviceCodePhaseOneResponse::stream` now takes `pipeline`, `tenant_id`,
  and `client_id` as arguments rather than storing them on the response;
  the response type mirrors only the JSON wire shape.
- `refresh_token::exchange` takes `&Pipeline` as its first argument so
  `DeviceCodeCredential` can share a single pipeline across requests.
- `TokenCache` and `DeviceCodeCredential.refresh_tokens` key on
  `BTreeSet<String>` rather than `Vec<String>`, so permutations of the same
  scope set collapse to a single cache entry instead of triggering redundant
  token acquisitions.
- `DeviceCodeAuthorization`'s `scope` field becomes `scopes: Vec<String>`
  exposed via `scopes() -> &[String]`, mirroring
  `RefreshTokenResponse::scopes()`. The wire `scope` is split on whitespace
  so leading, trailing, or repeated separators never produce empty entries.
- `DeviceCodeAuthorization` and `DeviceCodeErrorResponse` field visibility
  is tightened: all data is private with accessors, matching the secrets
  fields' existing pattern.
- `DeviceCodePhaseOneResponse.interval` is typed `u64` (was `i64`).
- `ChainedTokenCredentialOptions` derives `Clone` and `Copy`.
- `device_code` re-exports `DeviceCodeAuthorization` and
  `DeviceCodeErrorResponse` explicitly (was a glob re-export).
- `DeviceCodeErrorResponse::Display` surfaces `error_uri` when present.
- The `devicecode_credentials` module is renamed to `device_code_credential`
  to match the naming convention of sibling modules.
- The `cache` module is now `pub(crate)` — it never had any externally
  reachable items.
- The crate docs no longer carry "Originally from `azure_identity` 0.20.0"
  lineage notes; the modules have diverged substantially.
- `add_source` and `new` on `ChainedTokenCredential` document the
  ownership requirement (must add sources before sharing the `Arc`).

### Fixed

- Scope-order cache collisions in `TokenCache` and
  `DeviceCodeCredential.refresh_tokens`: `["a", "b"]` and `["b", "a"]`
  formerly produced different cache entries.
- `device_code::start()` and `refresh_token::exchange()` previously built
  a fresh `Pipeline` (and a fresh `reqwest::Client`) on every request,
  losing TLS sessions and HTTP connection pooling — especially harmful
  across the device-code polling loop. A single pipeline is now created
  per `DeviceCodeCredential` and threaded through.
- `AzureauthCliCredential` previously shelled out a `which`/`where`
  subprocess on every `get_token` call to locate the azureauth binary;
  the result is now cached in an `async_lock::OnceCell` and discovered
  at most once per credential lifetime.
- `AzureauthCliCredential` no longer drops the underlying `io::Error`
  context when the azureauth subprocess fails for reasons other than
  `NotFound`; the original `io::Error` is now preserved as the source.
- `start()`'s phase-one error path now wraps the parsed
  `DeviceCodeErrorResponse` via `Error::with_error` so the outer message
  retains the endpoint status while the parsed AAD error is the source.
- `DeviceCodeErrorResponse` tolerates missing `error_description` and
  `error_uri` (both OPTIONAL per RFC 6749 §5.2); without this the polling
  loop could fail to recognize an `authorization_pending` response that
  arrived with only `error` set, terminating polling.
- An `interval: 0` response can no longer turn the polling loop into a
  tight loop; the deserializer clamps to a one-second minimum.
- The `expiration_date` parse-error message in
  `azureauth_cli_credentials::unix_date_string` had an opening single
  quote with no closing quote.
- Several typo, dead-code, and doc-comment cleanups too small to enumerate
  individually.

### Removed

- `RefreshTokenError` (never deserialized into; replaced by structured
  `DeviceCodeErrorResponse` handling on both phase-one and phase-two paths
  for the device-code flow).
- `AzureauthCliCredential::add_mode`, `with_modes`, and `with_prompt_hint`
  fluent methods. They were uncallable in practice because `new()` returned
  `Arc<Self>`. Set the equivalents on `AzureauthCliCredentialOptions`
  instead.
- The unused `Cow<'a, str>` lifetime on `DeviceCodePhaseOneResponse`.
- Throwaway `Pipeline` and `default_pipeline()` allocations from the
  device-code `start()` path.
- A `#[allow(dead_code)]` attribute that's no longer needed since the
  fields it covered are now read.

## [0.1.0]

- Initial release. (Existing entries below this version predate this
  changelog; populate retroactively if useful.)
