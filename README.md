# AshAuthCode

Code-based authentication strategy for [Ash Authentication](https://hexdocs.pm/ash_authentication).

Instead of magic links (clicking a URL), users receive a short numeric code via email or SMS and enter it to authenticate.

## Installation

Add to your dependencies:

```elixir
def deps do
  [
    {:ash_auth_code, "~> 0.1.0"}
  ]
end
```

## Usage

Add the extension to your user resource:

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication, AshAuthCode],
    domain: MyApp.Accounts

  authentication do
    tokens do
      enabled? true
      token_resource MyApp.Accounts.Token
      signing_secret fn _, _ -> Application.fetch_env!(:my_app, :token_signing_secret) end
    end

    strategies do
      auth_code do
        identity_field :email
        code_length 6
        token_lifetime {10, :minutes}
        registration_enabled? true

        sender fn email, code, _opts ->
          MyApp.Emails.send_auth_code(email, code)
        end
      end
    end
  end

  attributes do
    uuid_primary_key :id
    attribute :email, :ci_string, allow_nil?: false
  end

  identities do
    identity :unique_email, [:email]
  end
end
```

## How It Works

1. **Request Phase**: User submits their email
   - Strategy generates a JWT token
   - Derives a short numeric code from the token (e.g., `847291`)
   - Calls your sender with the **code** (not the token)
   - Returns the token for server-side storage (e.g., in a cookie)

2. **Verify Phase**: User enters the code they received
   - Strategy receives both the token (from cookie) and code (from user)
   - Verifies the code matches the token
   - Signs in or registers the user

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `identity_field` | atom | `:email` | Field that uniquely identifies the user |
| `code_length` | integer | `6` | Length of the numeric code (4-10) |
| `token_lifetime` | integer or tuple | `{10, :minutes}` | How long the token is valid |
| `registration_enabled?` | boolean | `false` | Allow new user registration |
| `single_use_token?` | boolean | `true` | Revoke token after use |
| `sender` | function | required | Function to send the code |

## Sender Function

The sender receives:
- `identity` - The email/username (string for new users, user struct for existing)
- `code` - The derived numeric code (NOT the token)
- `opts` - Options including `:tenant`

```elixir
sender fn identity, code, opts ->
  email = if is_binary(identity), do: identity, else: identity.email
  MyApp.Emails.send_auth_code(email, code)
end
```

## HTTP Endpoints

The strategy creates two endpoints:

- `POST /user/auth_code/request` - Request a code
- `POST /user/auth_code/verify` - Verify code and sign in

## License

MIT
