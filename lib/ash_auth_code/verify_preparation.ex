defmodule AshAuthCode.AuthCode.VerifyPreparation do
  @moduledoc """
  Preparation for verifying an auth code during sign-in.

  Used when `registration_enabled?` is false.
  """
  use Ash.Resource.Preparation

  alias Ash.{Query, Resource, Resource.Preparation}
  alias AshAuthentication.{Info, Jwt, TokenResource}
  alias AshAuthCode.AuthCode

  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _opts, context) do
    strategy = Info.strategy_for_action!(query.resource, query.action.name)

    subject_name =
      query.resource
      |> Info.authentication_subject_name!()
      |> to_string()

    token = Query.get_argument(query, :token)
    code = Query.get_argument(query, :code)

    with true <- is_binary(token) and is_binary(code),
         true <- AuthCode.verify_code(token, code, strategy.code_length),
         {:ok, %{"act" => token_action, "sub" => subject, "identity" => identity}, _} <-
           Jwt.verify(token, query.resource, Ash.Context.to_opts(context), context),
         true <- to_string(strategy.verify_action_name) == token_action,
         %URI{path: ^subject_name} <- URI.parse(subject) do
      query
      |> Query.filter(^ref(strategy.identity_field) == ^identity)
      |> Query.after_action(fn _query, results ->
        case results do
          [user] ->
            revoke_single_use_token!(strategy, query, token, context)

            {:ok, auth_token, _claims} =
              Jwt.token_for_user(user, %{}, Ash.Context.to_opts(context))

            {:ok, [Resource.put_metadata(user, :token, auth_token)]}

          _ ->
            {:ok, []}
        end
      end)
    else
      _ ->
        Query.filter(query, false)
    end
  end

  defp revoke_single_use_token!(strategy, query, token, context) do
    if strategy.single_use_token? do
      token_resource = Info.authentication_tokens_token_resource!(query.resource)
      :ok = TokenResource.revoke(token_resource, token, Ash.Context.to_opts(context))
    end
  end
end
