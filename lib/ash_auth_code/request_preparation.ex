defmodule AshAuthCode.AuthCode.RequestPreparation do
  @moduledoc """
  Prepare a query for an auth code request.

  This preparation:
  1. Filters the query to match the identity field
  2. If a user is found, generates a token and derives the code
  3. Calls the sender with the code (not the token)
  4. Stores the token in metadata for the caller to persist

  Always returns an empty result to avoid leaking user existence.
  """
  use Ash.Resource.Preparation

  alias Ash.{Query, Resource, Resource.Preparation}
  alias AshAuthentication.Info
  alias AshAuthCode.AuthCode

  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _opts, context) do
    strategy = Info.strategy_for_action!(query.resource, query.action.name)

    identity_field = strategy.identity_field
    identity = Query.get_argument(query, identity_field)
    select_for_senders = Info.authentication_select_for_senders!(query.resource)

    if is_nil(identity) do
      Query.filter(query, false)
    else
      Query.filter(query, ^ref(identity_field) == ^identity)
    end
    |> Query.before_action(fn query ->
      query
      |> Ash.Query.ensure_selected(select_for_senders)
      |> Ash.Query.ensure_selected([identity_field])
    end)
    |> Query.after_action(&after_action(&1, &2, strategy, identity, context))
  end

  defp after_action(_query, [user], %{sender: {sender, send_opts}} = strategy, _identity, context) do
    context_opts = Ash.Context.to_opts(context)

    case AuthCode.request_token_for(strategy, user, context_opts, context) do
      {:ok, token, code} ->
        sender.send(user, code, Keyword.put(send_opts, :tenant, context.tenant))
        {:ok, [Resource.put_metadata(user, :token, token)]}

      _ ->
        {:ok, []}
    end
  end

  defp after_action(
         _query,
         _,
         %{registration_enabled?: true, sender: {sender, send_opts}} = strategy,
         identity,
         context
       )
       when not is_nil(identity) do
    context_opts = Ash.Context.to_opts(context)

    case AuthCode.request_token_for_identity(strategy, identity, context_opts, context) do
      {:ok, token, code} ->
        sender.send(to_string(identity), code, Keyword.put(send_opts, :tenant, context.tenant))

        fake_user =
          strategy.resource
          |> struct!(%{strategy.identity_field => identity})
          |> Resource.put_metadata(:token, token)

        {:ok, [fake_user]}

      _ ->
        {:ok, []}
    end
  end

  defp after_action(_, _, _, _, _) do
    {:ok, []}
  end
end
