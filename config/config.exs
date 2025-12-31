import Config

config :ash_auth_code, :token_signing_secret, "test_secret_at_least_32_characters_long"

import_config "#{config_env()}.exs"
