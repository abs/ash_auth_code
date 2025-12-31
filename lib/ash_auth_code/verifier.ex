defmodule AshAuthCode.AuthCode.Verifier do
  @moduledoc """
  DSL verifier for auth code strategy.

  Validates the strategy configuration after compilation.
  """

  alias AshAuthCode.AuthCode
  alias Spark.Error.DslError
  import AshAuthentication.Validations

  @doc false
  @spec verify(AuthCode.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with {:ok, _identity_attribute} <- find_attribute(dsl_state, strategy.identity_field),
         :ok <- validate_code_length(strategy.code_length),
         :ok <- validate_identity_for_registration(dsl_state, strategy) do
      :ok
    end
  end

  defp validate_identity_for_registration(_dsl_state, %{registration_enabled?: false}), do: :ok

  defp validate_identity_for_registration(dsl_state, strategy) do
    identity =
      Enum.find(Ash.Resource.Info.identities(dsl_state), fn identity ->
        identity.keys == [strategy.identity_field]
      end)

    if identity do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:authentication, :strategies, :auth_code],
         message:
           "registration_enabled? requires an identity on [:#{strategy.identity_field}] for upsert"
       )}
    end
  end

  defp validate_code_length(length) when length >= 4 and length <= 10, do: :ok

  defp validate_code_length(length) do
    {:error,
     DslError.exception(
       path: [:authentication, :strategies, :auth_code],
       message: "code_length must be between 4 and 10, got: #{length}"
     )}
  end
end
