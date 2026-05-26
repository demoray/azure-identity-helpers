# azure-identity-helpers

## Azure Identity Helpers

`azure-identity-helpers` provides unofficial utility components for handling
Azure authentication and identity management in Rust applications.

This crate offers helper components for Azure authentication scenarios,
including [AzureAuth CLI](https://github.com/AzureAD/microsoft-authentication-cli)
integration, credential chaining, device code authentication, and refresh
token handling.

### Modules

- `azureauth_cli_credentials`: Implements [AzureAuth CLI](https://github.com/AzureAD/microsoft-authentication-cli) based authentication.
- `chained_token_credential`: Implements credential chaining to try multiple authentication methods.
- `default_azure_credential`: Recreates [Go `DefaultAzureCredential`](https://learn.microsoft.com/en-us/azure/developer/go/sdk/authentication/credential-chains#defaultazurecredential-overview) using the currently supported Rust credential types. On non-`wasm32` targets, the default order is environment, workload identity, managed identity, Azure CLI, and Azure Developer CLI. On `wasm32`, the default order is environment, workload identity, and managed identity. `AzurePowerShellCredential` is not currently implemented in this crate.
- `device_code`: Provides device code flow authentication support for Azure services.
- `device_code_credential`: Implements a credential that can authenticate using device code flow. Uses the `device_code` module's functionality.
- `environment_credential`: Recreates an `EnvironmentCredential`-style helper for service principal authentication from environment variables.
- `oauth_error`: Shared OAuth 2.0 error response type (RFC 6749 §5.2) used by the device-code and refresh-token endpoints on failure.
- `refresh_token`: Handles refresh token operations for maintaining authentication sessions.


License: MIT
