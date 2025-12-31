defmodule AshAuthCode.AuthCode.Transformer do
  @moduledoc """
  DSL transformer for auth code strategy.

  Sets up the request and verify actions on the resource.
  """

  alias Ash.Resource
  alias AshAuthCode.AuthCode
  alias Spark.Dsl.Transformer
  import AshAuthentication.Validations
  import AshAuthentication.Utils
  import AshAuthentication.Strategy.Custom.Helpers

  @doc false
  @spec transform(AuthCode.t(), map) :: {:ok, AuthCode.t() | map} | {:error, any}
  def transform(strategy, dsl_state) do
    with :ok <-
           validate_token_generation_enabled(
             dsl_state,
             "Token generation must be enabled for auth code to work."
           ),
         strategy <- maybe_set_verify_action_name(strategy),
         strategy <- maybe_set_request_action_name(strategy),
         strategy <- maybe_set_lookup_action_name(strategy),
         strategy <- maybe_transform_token_lifetime(strategy),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             strategy.verify_action_name,
             &build_verify_action(&1, strategy)
           ),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             strategy.request_action_name,
             &build_request_action(&1, strategy)
           ) do
      dsl_state =
        dsl_state
        |> then(
          &register_strategy_actions(
            [
              strategy.verify_action_name,
              strategy.request_action_name,
              strategy.lookup_action_name
            ],
            &1,
            strategy
          )
        )
        |> put_strategy(strategy)

      {:ok, dsl_state}
    end
  end

  defp maybe_transform_token_lifetime(strategy) when is_integer(strategy.token_lifetime),
    do: %{strategy | token_lifetime: {strategy.token_lifetime, :minutes}}

  defp maybe_transform_token_lifetime(strategy), do: strategy

  defp maybe_set_verify_action_name(strategy) when is_nil(strategy.verify_action_name),
    do: %{strategy | verify_action_name: String.to_atom("verify_with_#{strategy.name}")}

  defp maybe_set_verify_action_name(strategy), do: strategy

  defp maybe_set_request_action_name(strategy) when is_nil(strategy.request_action_name),
    do: %{strategy | request_action_name: String.to_atom("request_#{strategy.name}")}

  defp maybe_set_request_action_name(strategy), do: strategy

  defp maybe_set_lookup_action_name(strategy) when is_nil(strategy.lookup_action_name),
    do: %{strategy | lookup_action_name: String.to_atom("get_by_#{strategy.identity_field}")}

  defp maybe_set_lookup_action_name(strategy), do: strategy

  defp build_verify_action(dsl_state, strategy) do
    if strategy.registration_enabled? do
      build_verify_create_action(dsl_state, strategy)
    else
      build_verify_read_action(dsl_state, strategy)
    end
  end

  defp build_verify_create_action(dsl_state, strategy) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
        name: :token,
        type: :string,
        allow_nil?: false
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
        name: :code,
        type: :string,
        allow_nil?: false
      )
    ]

    changes = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
        change: AshAuthCode.AuthCode.VerifyChange
      )
    ]

    metadata = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :metadata,
        name: :token,
        type: :string,
        allow_nil?: false
      )
    ]

    identity =
      Enum.find(Ash.Resource.Info.identities(dsl_state), fn identity ->
        identity.keys == [strategy.identity_field]
      end)

    Transformer.build_entity(Resource.Dsl, [:actions], :create,
      name: strategy.verify_action_name,
      arguments: arguments,
      changes: changes,
      metadata: metadata,
      upsert?: true,
      upsert_identity: identity.name,
      upsert_fields: [strategy.identity_field]
    )
  end

  defp build_verify_read_action(_dsl_state, strategy) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :token,
        type: :string,
        allow_nil?: false
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :code,
        type: :string,
        allow_nil?: false
      )
    ]

    preparations = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
        preparation: AshAuthCode.AuthCode.VerifyPreparation
      )
    ]

    metadata = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :metadata,
        name: :token,
        type: :string,
        allow_nil?: false
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: strategy.verify_action_name,
      arguments: arguments,
      preparations: preparations,
      metadata: metadata,
      get?: true
    )
  end

  defp build_request_action(dsl_state, strategy) do
    identity_attribute = Resource.Info.attribute(dsl_state, strategy.identity_field)

    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: strategy.identity_field,
        type: identity_attribute.type,
        allow_nil?: false
      )
    ]

    preparations = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
        preparation: AshAuthCode.AuthCode.RequestPreparation
      )
    ]

    metadata = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :metadata,
        name: :token,
        type: :string,
        allow_nil?: true
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: strategy.request_action_name,
      arguments: arguments,
      preparations: preparations,
      metadata: metadata
    )
  end
end
