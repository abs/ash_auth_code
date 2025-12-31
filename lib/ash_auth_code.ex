defmodule AshAuthCode do
  @moduledoc """
  Code-based authentication strategy for Ash Authentication.

  This strategy allows users to authenticate by entering a short numeric code
  sent to them via email or SMS, rather than clicking a magic link.

  ## Usage

  Add the extension to your user resource:

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

  ## Flow

  1. User submits their email to request a code
  2. The strategy generates a JWT token and derives a short code from it
  3. The sender callback receives the code (not the token) to send to the user
  4. The token is returned so it can be stored server-side (e.g., in a cookie)
  5. User enters the code they received
  6. The strategy verifies the code matches the stored token
  7. User is signed in or registered
  """

  use Spark.Dsl.Extension,
    dsl_patches:
      [
        %Spark.Dsl.Patch.AddEntity{
          section_path: [:authentication, :strategies],
          entity: AshAuthCode.AuthCode.Dsl.dsl()
        }
      ]
end
