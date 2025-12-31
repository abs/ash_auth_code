defimpl AshAuthentication.Strategy, for: AshAuthCode.AuthCode do
  @moduledoc false

  alias Ash.Resource
  alias AshAuthentication.{Info, Strategy}
  alias AshAuthCode.AuthCode
  alias Plug.Conn

  @doc false
  @spec name(AuthCode.t()) :: atom
  def name(strategy), do: strategy.name

  @doc false
  @spec phases(AuthCode.t()) :: [Strategy.phase()]
  def phases(_strategy), do: [:request, :verify]

  @doc false
  @spec actions(AuthCode.t()) :: [Strategy.action()]
  def actions(_strategy), do: [:request, :verify]

  @doc false
  @spec method_for_phase(AuthCode.t(), atom) :: Strategy.http_method()
  def method_for_phase(_strategy, :request), do: :post
  def method_for_phase(_strategy, :verify), do: :post

  @doc false
  @spec routes(AuthCode.t()) :: [Strategy.route()]
  def routes(strategy) do
    subject_name = Info.authentication_subject_name!(strategy.resource)

    [
      {"/#{subject_name}/#{strategy.name}/request", :request},
      {"/#{subject_name}/#{strategy.name}/verify", :verify}
    ]
  end

  @doc false
  @spec plug(AuthCode.t(), Strategy.phase(), Conn.t()) :: Conn.t()
  def plug(strategy, :request, conn), do: AuthCode.Plug.request(conn, strategy)
  def plug(strategy, :verify, conn), do: AuthCode.Plug.verify(conn, strategy)

  @doc false
  @spec action(AuthCode.t(), Strategy.action(), map, keyword) ::
          :ok | {:ok, Resource.record()} | {:error, any}
  def action(strategy, :request, params, options),
    do: AuthCode.Actions.request(strategy, params, options)

  def action(strategy, :verify, params, options),
    do: AuthCode.Actions.verify(strategy, params, options)

  @doc false
  @spec tokens_required?(AuthCode.t()) :: boolean
  def tokens_required?(_), do: true
end
