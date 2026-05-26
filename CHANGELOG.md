# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because the crate is still pre-1.0, breaking changes may land in any `0.x.y`
release per SemVer §4. They are called out explicitly in the **Changed**
and **Removed** sections.

## [Unreleased]

### Added

- `DeviceCodeCredentialOptions` carrying an async `message_handler` callback
  ([#126](https://github.com/demoray/azure-identity-helpers/pull/126)) and a caller-supplied HTTP `Pipeline` ([#127](https://github.com/demoray/azure-identity-helpers/pull/127)) instead of the
  default `eprintln!` / per-credential pipeline.
- `AzureauthCliCredentialOptions` with `modes` and `prompt_hint` fields,
  replacing the previously unreachable fluent builder methods on
  `AzureauthCliCredential` ([#147](https://github.com/demoray/azure-identity-helpers/pull/147)).
- `RefreshTokenResponse::expires_on()` ([#138](https://github.com/demoray/azure-identity-helpers/pull/138)) and
  `DeviceCodeAuthorization::expires_on()` ([#140](https://github.com/demoray/azure-identity-helpers/pull/140)) accessors that return an
  absolute `OffsetDateTime` anchored at deserialize time, so repeated reads
  of the same response don't drift forward with the wall clock.
- `DeviceCodeAuthorization::token_type()`, `scopes()`, and `expires_in()`
  accessors ([#140](https://github.com/demoray/azure-identity-helpers/pull/140)).
- `start()` parses `DeviceCodeErrorResponse` on phase-one failure and wraps
  it as the source of the returned error, matching `stream()`'s behavior
  on phase-two ([#141](https://github.com/demoray/azure-identity-helpers/pull/141)).
- `rust-version = "1.91"` declared in `Cargo.toml`, enabling
  `clippy::incompatible_msrv` enforcement ([#148](https://github.com/demoray/azure-identity-helpers/pull/148)).
- Polling interval rejected at deserialize time when outside `0..=i64::MAX`
  ([#143](https://github.com/demoray/azure-identity-helpers/pull/143)) and clamped to a one-second minimum so an `interval: 0` from
  the server can't cause a tight loop ([#144](https://github.com/demoray/azure-identity-helpers/pull/144)).
- Significant test coverage: `Send` bounds on every public async
  constructor ([#122](https://github.com/demoray/azure-identity-helpers/pull/122)), `MockCredential`-driven chain semantics ([#123](https://github.com/demoray/azure-identity-helpers/pull/123)),
  `format_aggregate_error` source-chain walking ([#133](https://github.com/demoray/azure-identity-helpers/pull/133)), azureauth binary
  lookup caching ([#134](https://github.com/demoray/azure-identity-helpers/pull/134)), `expires_on()` stability ([#138](https://github.com/demoray/azure-identity-helpers/pull/138), [#140](https://github.com/demoray/azure-identity-helpers/pull/140)),
  optional-field tolerance on `DeviceCodeErrorResponse` ([#142](https://github.com/demoray/azure-identity-helpers/pull/142)),
  polling-interval bounds ([#143](https://github.com/demoray/azure-identity-helpers/pull/143), [#144](https://github.com/demoray/azure-identity-helpers/pull/144)), options-struct plumbing through
  to the CLI ([#147](https://github.com/demoray/azure-identity-helpers/pull/147)), and scope-splitting on messy whitespace ([#149](https://github.com/demoray/azure-identity-helpers/pull/149)).

### Changed

The crate is pre-1.0. Every entry in this section is a breaking API change
under SemVer §4.

- `DeviceCodeCredential::new` ([#126](https://github.com/demoray/azure-identity-helpers/pull/126)) and `AzureauthCliCredential::new`
  ([#147](https://github.com/demoray/azure-identity-helpers/pull/147)) follow the options-struct constructor pattern. Both options
  structs are `#[non_exhaustive]`.
- `AzureauthCliCredential::new` returns `Arc<Self>` directly instead of
  `azure_core::Result<Arc<Self>>` ([#147](https://github.com/demoray/azure-identity-helpers/pull/147)).
- `device_code::start` takes `&Pipeline` ([#125](https://github.com/demoray/azure-identity-helpers/pull/125), [#127](https://github.com/demoray/azure-identity-helpers/pull/127)) and
  `tenant_id: &str` ([#129](https://github.com/demoray/azure-identity-helpers/pull/129), [#130](https://github.com/demoray/azure-identity-helpers/pull/130)); `DeviceCodePhaseOneResponse` lost
  its lifetime parameter ([#129](https://github.com/demoray/azure-identity-helpers/pull/129)).
- `DeviceCodePhaseOneResponse::stream` takes `pipeline`, `tenant_id`, and
  `client_id` as arguments; the response type mirrors only the JSON wire
  shape ([#130](https://github.com/demoray/azure-identity-helpers/pull/130)).
- `refresh_token::exchange` takes `&Pipeline` as its first argument so
  `DeviceCodeCredential` can share a single pipeline across requests
  ([#125](https://github.com/demoray/azure-identity-helpers/pull/125)).
- `TokenCache` ([#124](https://github.com/demoray/azure-identity-helpers/pull/124)) and `DeviceCodeCredential.refresh_tokens` ([#128](https://github.com/demoray/azure-identity-helpers/pull/128))
  key on `BTreeSet<String>` rather than `Vec<String>`.
- `DeviceCodeAuthorization`'s `scope: String` becomes
  `scopes: Vec<String>` exposed via `scopes() -> &[String]` ([#149](https://github.com/demoray/azure-identity-helpers/pull/149)),
  splitting on whitespace so leading/trailing/repeated separators never
  produce empty entries ([#149](https://github.com/demoray/azure-identity-helpers/pull/149)).
- `DeviceCodeAuthorization` ([#140](https://github.com/demoray/azure-identity-helpers/pull/140)) and `DeviceCodeErrorResponse`
  ([#142](https://github.com/demoray/azure-identity-helpers/pull/142)) field visibility tightened: all data is private with
  accessors.
- `DeviceCodePhaseOneResponse.interval` is typed `u64` ([#143](https://github.com/demoray/azure-identity-helpers/pull/143)).
- `ChainedTokenCredentialOptions` derives `Clone` and `Copy` ([#132](https://github.com/demoray/azure-identity-helpers/pull/132)).
- `device_code` re-exports `DeviceCodeAuthorization` and
  `DeviceCodeErrorResponse` explicitly ([#150](https://github.com/demoray/azure-identity-helpers/pull/150)).
- `DeviceCodeErrorResponse::Display` surfaces `error_uri` when present
  ([#142](https://github.com/demoray/azure-identity-helpers/pull/142)).
- `devicecode_credentials` module renamed to `device_code_credential`
  ([#152](https://github.com/demoray/azure-identity-helpers/pull/152)).
- `cache` module is now `pub(crate)` ([#151](https://github.com/demoray/azure-identity-helpers/pull/151)).
- Crate docs no longer carry "Originally from `azure_identity` 0.20.0"
  lineage notes ([#153](https://github.com/demoray/azure-identity-helpers/pull/153)).
- `add_source` and `new` on `ChainedTokenCredential` document the
  ownership requirement (must add sources before sharing the `Arc`)
  ([#139](https://github.com/demoray/azure-identity-helpers/pull/139)).

### Fixed

- Scope-order cache collisions in `TokenCache` ([#124](https://github.com/demoray/azure-identity-helpers/pull/124)) and
  `DeviceCodeCredential.refresh_tokens` ([#128](https://github.com/demoray/azure-identity-helpers/pull/128)): permutations of the
  same scope set formerly produced different entries.
- `device_code::start()` and `refresh_token::exchange()` previously built
  a fresh `Pipeline` (and `reqwest::Client`) on every request, losing TLS
  and HTTP pooling — especially harmful across the device-code polling
  loop. A single pipeline is now created per `DeviceCodeCredential` and
  threaded through ([#125](https://github.com/demoray/azure-identity-helpers/pull/125)).
- `AzureauthCliCredential` previously shelled out a `which`/`where`
  subprocess on every `get_token` call to locate the azureauth binary;
  the result is now cached and discovered at most once per credential
  lifetime ([#134](https://github.com/demoray/azure-identity-helpers/pull/134)).
- `AzureauthCliCredential` preserves the underlying `io::Error` when the
  azureauth subprocess fails for reasons other than `NotFound` ([#121](https://github.com/demoray/azure-identity-helpers/pull/121)).
- `start()`'s phase-one error path wraps the parsed
  `DeviceCodeErrorResponse` via `Error::with_error` so the outer message
  retains the endpoint status while the parsed AAD error is the source
  ([#141](https://github.com/demoray/azure-identity-helpers/pull/141)).
- `DeviceCodeErrorResponse` tolerates missing `error_description` and
  `error_uri` (both OPTIONAL per RFC 6749 §5.2) — without this the
  polling loop could fail to recognize an `authorization_pending`
  response with only `error` set ([#142](https://github.com/demoray/azure-identity-helpers/pull/142)).
- `interval: 0` no longer turns the polling loop into a tight loop on
  the AAD token endpoint; the deserializer clamps to a one-second
  minimum ([#144](https://github.com/demoray/azure-identity-helpers/pull/144)).
- `unix_date_string`'s `expiration_date` parse-error message had an
  opening single quote with no closing quote ([#136](https://github.com/demoray/azure-identity-helpers/pull/136)).
- Small typo / dead-code / doc-comment cleanups ([#119](https://github.com/demoray/azure-identity-helpers/pull/119), [#120](https://github.com/demoray/azure-identity-helpers/pull/120), [#135](https://github.com/demoray/azure-identity-helpers/pull/135),
  [#137](https://github.com/demoray/azure-identity-helpers/pull/137), [#145](https://github.com/demoray/azure-identity-helpers/pull/145), [#146](https://github.com/demoray/azure-identity-helpers/pull/146)).

### Removed

- `RefreshTokenError` (never deserialized into) ([#131](https://github.com/demoray/azure-identity-helpers/pull/131)).
- `AzureauthCliCredential::add_mode`, `with_modes`, and
  `with_prompt_hint` fluent methods — uncallable in practice because
  `new()` returned `Arc<Self>`; configure via `AzureauthCliCredentialOptions`
  instead ([#147](https://github.com/demoray/azure-identity-helpers/pull/147)).
- The unused `Cow<'a, str>` lifetime on `DeviceCodePhaseOneResponse`
  ([#129](https://github.com/demoray/azure-identity-helpers/pull/129)).
- Throwaway `Pipeline` allocations from the device-code `start()` path
  ([#130](https://github.com/demoray/azure-identity-helpers/pull/130)).
- A `#[allow(dead_code)]` attribute that's no longer needed since the
  fields it covered are now read ([#120](https://github.com/demoray/azure-identity-helpers/pull/120)).

## [0.1.0] - 2026-05-12

### Changed

- Routine dependency refresh ([#117](https://github.com/demoray/azure-identity-helpers/pull/117)).

## [0.0.18] - 2026-05-05

### Fixed

- Device-code polling now honors RFC 8628 §3.5: `authorization_pending`
  and `slow_down` keep the loop alive (the latter extends the polling
  interval by 5s), and terminal server errors (e.g. `expired_token`,
  `access_denied`) are surfaced rather than swallowed ([#114](https://github.com/demoray/azure-identity-helpers/pull/114)).

## [0.0.17] - 2026-04-23

### Changed

- Address updated clippy lints ([#111](https://github.com/demoray/azure-identity-helpers/pull/111)).
- Routine dependency refresh ([#107](https://github.com/demoray/azure-identity-helpers/pull/107), [#110](https://github.com/demoray/azure-identity-helpers/pull/110)).

## [0.0.16] - 2026-04-09

### Changed

- Routine dependency refresh ([#102](https://github.com/demoray/azure-identity-helpers/pull/102), [#103](https://github.com/demoray/azure-identity-helpers/pull/103), [#104](https://github.com/demoray/azure-identity-helpers/pull/104)).

## [0.0.15] - 2026-03-19

### Added

- `DefaultAzureCredential` and `EnvironmentCredential`, ported from the
  pre-1.0 `azure_identity` 0.20.0 shape that newer upstream releases
  dropped ([#98](https://github.com/demoray/azure-identity-helpers/pull/98)).

## [0.0.14] - 2026-03-11

First tagged release in the public history (older `0.0.x` releases predate
the changelog). The crate began as a place to keep helper credentials that
either weren't available in the official `azure_identity` crate or had
been removed across its breaking releases.

### Added

- `AzureauthCliCredential`, wrapping the [AzureAuth
  CLI](https://github.com/AzureAD/microsoft-authentication-cli), plus
  the `find_azureauth` helper for locating the executable on `PATH`
  ([#7](https://github.com/demoray/azure-identity-helpers/pull/7), [#13](https://github.com/demoray/azure-identity-helpers/pull/13)).
- `DeviceCodeCredential` and the underlying `device_code` flow
  (`start`, `DeviceCodePhaseOneResponse::stream`, `DeviceCodeAuthorization`,
  `DeviceCodeErrorResponse`) ([#6](https://github.com/demoray/azure-identity-helpers/pull/6), [#12](https://github.com/demoray/azure-identity-helpers/pull/12)).
- `refresh_token::exchange` and `RefreshTokenResponse` ([#6](https://github.com/demoray/azure-identity-helpers/pull/6)).
- `TokenCache` (internal) and `ChainedTokenCredential` for composing
  multiple credential sources with caching.
- Lint specification in `Cargo.toml` opting into `pedantic`, `nursery`,
  `cargo`, `perf`, `style`, `correctness`, `suspicious`, plus
  `unwrap_used` / `expect_used` / `panic` / `indexing_slicing` at the
  crate root ([#65](https://github.com/demoray/azure-identity-helpers/pull/65)).
- HTTP pipeline support for the device-code and refresh-token requests
  ([#55](https://github.com/demoray/azure-identity-helpers/pull/55)).
- Per-source logging in `ChainedTokenCredential` ([#8](https://github.com/demoray/azure-identity-helpers/pull/8)).

### Changed

- `AzureauthCliCredential` aligned to look like other credential
  providers in the crate ([#7](https://github.com/demoray/azure-identity-helpers/pull/7)).
- `parking_lot::Mutex` replaced with the existing `async_lock::Mutex`
  to avoid a synchronous-only dep in async-only code ([#11](https://github.com/demoray/azure-identity-helpers/pull/11)).
- Dependencies pinned with `default-features = false`; opt-in features
  enabled explicitly so downstream consumers don't drag in surprise
  transitive deps ([#81](https://github.com/demoray/azure-identity-helpers/pull/81), [#85](https://github.com/demoray/azure-identity-helpers/pull/85)).
- Tracked upstream `azure_identity` / `azure_core` releases through
  0.23, 0.24, 0.25, and 0.29 ([#20](https://github.com/demoray/azure-identity-helpers/pull/20), [#24](https://github.com/demoray/azure-identity-helpers/pull/24), [#29](https://github.com/demoray/azure-identity-helpers/pull/29), [#36](https://github.com/demoray/azure-identity-helpers/pull/36), [#64](https://github.com/demoray/azure-identity-helpers/pull/64)).

### Fixed

- Initial `DeviceCodeCredential` error-code handling ([#15](https://github.com/demoray/azure-identity-helpers/pull/15)).
