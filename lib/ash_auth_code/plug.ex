defmodule AshAuthCode.AuthCode.Plug do
  @moduledoc """
  Plugs for the auth code strategy.

  Handles HTTP requests for requesting codes and verifying them.
  """

  alias AshAuthentication.{Info, Strategy}
  alias AshAuthCode.AuthCode
  alias Plug.Conn
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  @doc """
  Handle a request for an auth code.

  Retrieves form parameters from nested within the subject name, generates a token,
  derives the code, sends it via the configured sender, and stores the token
  in the response for the caller to persist (e.g., in a cookie).
  """
  @spec request(Conn.t(), AuthCode.t()) :: Conn.t()
  def request(conn, strategy) do
    params = subject_params(conn, strategy)
    opts = opts(conn)
    result = Strategy.action(strategy, :request, params, opts)
    store_authentication_result(conn, result)
  end

  @doc """
  Handle verification of an auth code.

  Expects both the token (typically from a cookie) and the code (from user input).
  Verifies they match and signs in the user.
  """
  @spec verify(Conn.t(), AuthCode.t()) :: Conn.t()
  def verify(conn, strategy) do
    param_name =
      strategy.resource
      |> Info.authentication_subject_name!()
      |> to_string()

    params =
      case Map.fetch(conn.params, param_name) do
        :error -> conn.params
        {:ok, params} -> params
      end

    opts = opts(conn)
    result = Strategy.action(strategy, :verify, params, opts)
    store_authentication_result(conn, result)
  end

  defp subject_params(conn, strategy) do
    subject_name =
      strategy.resource
      |> Info.authentication_subject_name!()
      |> to_string()

    Map.get(conn.params, subject_name, %{})
  end

  defp opts(conn) do
    [actor: get_actor(conn), tenant: get_tenant(conn), context: get_context(conn) || %{}]
    |> Enum.reject(&is_nil(elem(&1, 1)))
  end
end
