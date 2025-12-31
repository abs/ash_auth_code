defmodule AshAuthCode.AuthCode.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.Custom
  alias AshAuthCode.AuthCode
  alias Spark.Dsl.Entity

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    %Entity{
      name: :auth_code,
      describe: "Strategy for authenticating using a short numeric code",
      args: [{:optional, :name, :auth_code}],
      hide: [:name],
      target: AuthCode,
      no_depend_modules: [:sender],
      schema: [
        name: [
          type: :atom,
          doc: "Uniquely identifies the strategy.",
          required: true
        ],
        identity_field: [
          type: :atom,
          doc: "The name of the attribute which uniquely identifies the user (e.g., `email`).",
          default: :email
        ],
        code_length: [
          type: :pos_integer,
          doc: "The length of the numeric code to generate.",
          default: 6
        ],
        token_lifetime: [
          type:
            {:or,
             [
               :pos_integer,
               {:tuple, [:pos_integer, {:in, [:days, :hours, :minutes, :seconds]}]}
             ]},
          doc: "How long the token is valid. If no unit is provided, then `minutes` is assumed.",
          default: {10, :minutes}
        ],
        registration_enabled?: [
          type: :boolean,
          doc:
            "Allow new user registration via auth code. When true, the verify action becomes an upsert.",
          default: false
        ],
        request_action_name: [
          type: :atom,
          doc: "The name to use for the request action. Defaults to `request_<strategy_name>`",
          required: false
        ],
        lookup_action_name: [
          type: :atom,
          doc:
            "The action to use when looking up a user by their identity. Defaults to `get_by_<identity_field>`"
        ],
        single_use_token?: [
          type: :boolean,
          doc: "Automatically revoke the token once it's been used for verification.",
          default: true
        ],
        verify_action_name: [
          type: :atom,
          doc: "The name to use for the verify action. Defaults to `verify_with_<strategy_name>`",
          required: false
        ],
        sender: [
          type:
            {:spark_function_behaviour, AshAuthentication.Sender,
             {AshAuthentication.SenderFunction, 3}},
          doc: """
          How to send the code to the user.

          The sender receives the identity (email/username), the derived code (NOT the token),
          and options including the tenant.

          Example:

              sender fn email, code, opts ->
                MyApp.Emails.send_auth_code(email, code)
              end
          """,
          required: true
        ]
      ]
    }
  end
end
