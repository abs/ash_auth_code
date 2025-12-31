defmodule AshAuthCode.AuthCode.VerifyChange do
  @moduledoc """
  Change for verifying an auth code during registration/upsert.

  Used when `registration_enabled?` is true.
  """
  use Ash.Resource.Change

  alias Ash.{Changeset, Resource, Resource.Change}
  alias AshAuthentication.{Errors.InvalidToken, Info, Jwt, TokenResource}
  alias AshAuthCode.AuthCode

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.Context.t()) :: Changeset.t()
  def change(changeset, opts, context) do
    subject_name =
      changeset.resource
      |> Info.authentication_subject_name!()
      |> to_string()

    case Info.find_strategy(changeset, context, opts) do
      {:ok, strategy} ->
        with {:got_token, token} when is_binary(token) <-
               {:got_token, Changeset.get_argument(changeset, :token)},
             {:got_code, code} when is_binary(code) <-
               {:got_code, Changeset.get_argument(changeset, :code)},
             {:code_valid, true} <-
               {:code_valid, AuthCode.verify_code(token, code, strategy.code_length)},
             {:verified,
              {:ok, %{"act" => token_action, "sub" => subject, "identity" => identity}, _}} <-
               {:verified,
                Jwt.verify(token, changeset.resource, Ash.Context.to_opts(context), context)},
             {:action, ^token_action} <-
               {:action, to_string(strategy.verify_action_name)},
             {:subject_matches, %URI{path: ^subject_name}} <-
               {:subject_matches, URI.parse(subject)} do
          changeset
          |> Changeset.force_change_attribute(strategy.identity_field, identity)
          |> Changeset.after_transaction(fn
            _changeset, {:ok, record} ->
              revoke_single_use_token!(strategy, changeset, token, context)

              {:ok, auth_token, _claims} =
                Jwt.token_for_user(record, %{}, Ash.Context.to_opts(context))

              {:ok, Resource.put_metadata(record, :token, auth_token)}

            _changeset, {:error, error} ->
              {:error, error}
          end)
        else
          e ->
            {field, reason} = error_field_and_reason(e)

            Ash.Changeset.add_error(
              changeset,
              InvalidToken.exception(
                field: field,
                reason: reason,
                type: :auth_code
              )
            )
        end

      _ ->
        Ash.Changeset.add_error(
          changeset,
          "No strategy in context, and no strategy found for action #{inspect(changeset.resource)}.#{changeset.action.name}"
        )
    end
  end

  defp revoke_single_use_token!(strategy, changeset, token, context) do
    if strategy.single_use_token? do
      token_resource = Info.authentication_tokens_token_resource!(changeset.resource)
      :ok = TokenResource.revoke(token_resource, token, Ash.Context.to_opts(context))
    end
  end

  defp error_field_and_reason(e) do
    case e do
      {:got_token, nil} -> {:token, "No token supplied"}
      {:got_token, _} -> {:token, "Token must be a string"}
      {:got_code, nil} -> {:code, "No code supplied"}
      {:got_code, _} -> {:code, "Code must be a string"}
      {:code_valid, false} -> {:code, "Invalid code"}
      {:verified, _} -> {:token, "Token verification failed"}
      {:action, _} -> {:token, "Token was not issued for this action"}
      {:subject_matches, _} -> {:token, "Token subject mismatch"}
    end
  end
end
