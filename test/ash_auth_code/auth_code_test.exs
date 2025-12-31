defmodule AshAuthCode.AuthCodeTest do
  use ExUnit.Case, async: true

  alias AshAuthCode.AuthCode

  describe "derive_code_from_token/2" do
    test "generates a 6-digit code by default" do
      token = "some_jwt_token_here"
      code = AuthCode.derive_code_from_token(token)

      assert String.length(code) == 6
      assert String.match?(code, ~r/^\d{6}$/)
    end

    test "generates consistent codes for the same token" do
      token = "test_token_12345"

      code1 = AuthCode.derive_code_from_token(token)
      code2 = AuthCode.derive_code_from_token(token)

      assert code1 == code2
    end

    test "generates different codes for different tokens" do
      code1 = AuthCode.derive_code_from_token("token_a")
      code2 = AuthCode.derive_code_from_token("token_b")

      assert code1 != code2
    end

    test "respects custom code length" do
      token = "some_token"

      assert String.length(AuthCode.derive_code_from_token(token, 4)) == 4
      assert String.length(AuthCode.derive_code_from_token(token, 8)) == 8
      assert String.length(AuthCode.derive_code_from_token(token, 10)) == 10
    end

    test "pads codes with leading zeros when needed" do
      tokens = for i <- 1..100, do: "token_#{i}"

      codes = Enum.map(tokens, &AuthCode.derive_code_from_token/1)

      Enum.each(codes, fn code ->
        assert String.length(code) == 6
      end)
    end
  end

  describe "verify_code/3" do
    test "returns true for matching code" do
      token = "my_secret_token"
      code = AuthCode.derive_code_from_token(token)

      assert AuthCode.verify_code(token, code) == true
    end

    test "returns false for non-matching code" do
      token = "my_secret_token"

      assert AuthCode.verify_code(token, "000000") == false
      assert AuthCode.verify_code(token, "123456") == false
    end

    test "returns false for wrong token" do
      token1 = "token_one"
      token2 = "token_two"
      code = AuthCode.derive_code_from_token(token1)

      assert AuthCode.verify_code(token2, code) == false
    end

    test "respects custom code length" do
      token = "some_token"
      code_4 = AuthCode.derive_code_from_token(token, 4)
      code_8 = AuthCode.derive_code_from_token(token, 8)

      assert AuthCode.verify_code(token, code_4, 4) == true
      assert AuthCode.verify_code(token, code_8, 8) == true
      assert AuthCode.verify_code(token, code_4, 6) == false
    end
  end

  describe "strategy struct" do
    test "has correct default values" do
      strategy = %AuthCode{}

      assert strategy.identity_field == :email
      assert strategy.code_length == 6
      assert strategy.token_lifetime == {10, :minutes}
      assert strategy.registration_enabled? == false
      assert strategy.single_use_token? == true
      assert strategy.name == :auth_code
    end
  end
end
