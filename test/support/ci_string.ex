# Mock CiString for testing identity serialization
defmodule AshAuthCode.Test.CiString do
  defstruct [:string]

  defimpl String.Chars do
    def to_string(%{string: string}), do: string
  end
end
