defmodule AshAuthCode.MixProject do
  use Mix.Project

  @version "0.1.0"
  @description "Code-based authentication strategy for Ash Authentication"

  def project do
    [
      app: :ash_auth_code,
      version: @version,
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      description: @description,
      docs: docs(),
      source_url: "https://github.com/abs/ash_auth_code",
      homepage_url: "https://github.com/abs/ash_auth_code"
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:ash_authentication, "~> 4.0"},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      maintainers: ["Andrei Soroker"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/abs/ash_auth_code"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md"]
    ]
  end
end
