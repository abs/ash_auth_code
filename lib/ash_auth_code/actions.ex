defmodule AshAuthCode.AuthCode.Actions do
  @moduledoc """
  Actions for the auth code strategy.

  Provides the code interface for requesting codes and verifying them.
  """

  alias Ash.{Changeset, Query, Resource}
  alias AshAuthentication.{Errors, Info}
  alias AshAuthCode.AuthCode

  @doc """
  Request an auth code for a user.

  Generates a token, derives the code, calls the sender, and returns the token
  in the result metadata so it can be stored server-side.
  """
  @spec request(AuthCode.t(), map, keyword) :: {:ok, map} | {:error, any}
  def request(strategy, params, options) do
    options =
      options
      |> Keyword.put_new_lazy(:domain, fn ->
        Info.domain!(strategy.resource)
      end)

    strategy.resource
    |> Query.new()
    |> Query.set_context(%{private: %{ash_authentication?: true}})
    |> Query.for_read(strategy.request_action_name, params, options)
    |> Ash.read()
    |> case do
      {:ok, [result]} ->
        {:ok, %{token: Resource.get_metadata(result, :token)}}

      {:ok, []} ->
        {:ok, %{token: nil}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Verify a code and sign in the user.

  Takes the token (from server-side storage) and the code (from user input),
  verifies they match, and returns the authenticated user.
  """
  @spec verify(AuthCode.t(), map, keyword) ::
          {:ok, Resource.record()} | {:error, Errors.AuthenticationFailed.t()}
  def verify(strategy, params, options) do
    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

    if strategy.registration_enabled? do
      strategy.resource
      |> Changeset.new()
      |> Changeset.set_context(%{private: %{ash_authentication?: true}})
      |> Changeset.for_create(strategy.verify_action_name, params, options)
      |> Ash.create()
      |> case do
        {:ok, record} ->
          {:ok, record}

        {:error, error} ->
          {:error,
           Errors.AuthenticationFailed.exception(
             strategy: strategy,
             caused_by: error
           )}
      end
    else
      strategy.resource
      |> Query.new()
      |> Query.set_context(%{private: %{ash_authentication?: true}})
      |> Query.for_read(strategy.verify_action_name, params, options)
      |> Ash.read()
      |> case do
        {:ok, [user]} ->
          {:ok, user}

        {:ok, []} ->
          {:error,
           Errors.AuthenticationFailed.exception(
             strategy: strategy,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: :verify,
               message: "Invalid code or token"
             }
           )}

        {:ok, _users} ->
          {:error,
           Errors.AuthenticationFailed.exception(
             strategy: strategy,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: :verify,
               message: "Query returned too many users"
             }
           )}

        {:error, error} when is_exception(error) ->
          {:error,
           Errors.AuthenticationFailed.exception(
             strategy: strategy,
             caused_by: error
           )}

        {:error, error} ->
          {:error,
           Errors.AuthenticationFailed.exception(
             strategy: strategy,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: :verify,
               message: "Verification failed: #{inspect(error)}"
             }
           )}
      end
    end
  end
end
