defmodule AshAuthCode.AuthCode do
  @moduledoc """
  Strategy for authentication using a short numeric code.

  Unlike magic links where users click a URL containing the token, this strategy:
  1. Generates a JWT token and derives a short code from it
  2. Sends only the code to the user (via email, SMS, etc.)
  3. Stores the token server-side (cookie, session, etc.)
  4. Verifies the code matches the token when the user submits it

  ## Requirements

  1. Have a primary key
  2. A uniquely constrained identity field (eg `username` or `email`)
  3. Have tokens enabled

  ## Example

      defmodule MyApp.Accounts.User do
        use Ash.Resource,
          extensions: [AshAuthentication, AshAuthCode],
          domain: MyApp.Accounts

        authentication do
          strategies do
            auth_code do
              identity_field :email
              code_length 6
              sender fn email, code, _opts ->
                MyApp.Emails.send_auth_code(email, code)
              end
            end
          end
        end

        identities do
          identity :unique_email, [:email]
        end
      end
  """

  alias __MODULE__.{Dsl, Transformer, Verifier}

  defstruct identity_field: :email,
            code_length: 6,
            lookup_action_name: nil,
            name: :auth_code,
            registration_enabled?: false,
            request_action_name: nil,
            resource: nil,
            sender: nil,
            verify_action_name: nil,
            single_use_token?: true,
            token_lifetime: {10, :minutes},
            __spark_metadata__: nil

  use AshAuthentication.Strategy.Custom, entity: Dsl.dsl()

  alias AshAuthentication.Jwt

  @type t :: %__MODULE__{
          identity_field: atom,
          code_length: pos_integer,
          lookup_action_name: atom | nil,
          name: atom,
          registration_enabled?: boolean,
          request_action_name: atom | nil,
          resource: module,
          sender: {module, keyword},
          verify_action_name: atom | nil,
          single_use_token?: boolean,
          token_lifetime: pos_integer | {pos_integer, :days | :hours | :minutes | :seconds},
          __spark_metadata__: Spark.Dsl.Entity.spark_meta()
        }

  defdelegate transform(strategy, dsl_state), to: Transformer
  defdelegate verify(strategy, dsl_state), to: Verifier

  @doc """
  Derives a numeric code of the configured length from a token.

  Uses SHA256 hashing to ensure the same token always produces the same code.
  """
  @spec derive_code_from_token(binary, pos_integer) :: binary
  def derive_code_from_token(token, code_length \\ 6) when is_binary(token) do
    max_value = Integer.pow(10, code_length)

    token
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16()
    |> String.slice(0, code_length * 2)
    |> String.to_integer(16)
    |> rem(max_value)
    |> Integer.to_string()
    |> String.pad_leading(code_length, "0")
  end

  @doc """
  Verifies that a given code matches the code derived from the token.
  """
  @spec verify_code(binary, binary, pos_integer) :: boolean
  def verify_code(token, code, code_length \\ 6)
      when is_binary(token) and is_binary(code) do
    derive_code_from_token(token, code_length) == code
  end

  @doc """
  Generate a token for a user and return both the token and derived code.
  """
  @spec request_token_for(t, Ash.Resource.record(), keyword, map) ::
          {:ok, token :: binary, code :: binary} | :error
  def request_token_for(strategy, user, opts \\ [], context \\ %{})
      when is_struct(strategy, __MODULE__) and is_struct(user, strategy.resource) do
    case Jwt.token_for_user(
           user,
           %{
             "act" => strategy.verify_action_name,
             "identity" => user |> Map.get(strategy.identity_field) |> to_string()
           },
           Keyword.merge(opts,
             token_lifetime: strategy.token_lifetime,
             purpose: :auth_code
           ),
           context
         ) do
      {:ok, token, _claims} ->
        code = derive_code_from_token(token, strategy.code_length)
        {:ok, token, code}

      :error ->
        :error
    end
  end

  @doc """
  Generate a token for an identity (email/username) and return both the token and derived code.

  Used when registration is enabled and the user doesn't exist yet.
  """
  @spec request_token_for_identity(t, binary, keyword, map) ::
          {:ok, token :: binary, code :: binary} | :error
  def request_token_for_identity(strategy, identity, opts \\ [], context \\ %{})
      when is_struct(strategy, __MODULE__) do
    case Jwt.token_for_resource(
           strategy.resource,
           %{
             "act" => strategy.verify_action_name,
             "identity" => to_string(identity)
           },
           Keyword.merge(opts, token_lifetime: strategy.token_lifetime, purpose: :auth_code),
           context
         ) do
      {:ok, token, _claims} ->
        code = derive_code_from_token(token, strategy.code_length)
        {:ok, token, code}

      :error ->
        :error
    end
  end
end
