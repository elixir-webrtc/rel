import Config

config :ex_turn,
  public_ip: {127, 0, 0, 1},
  listen_ip: {0, 0, 0, 0},
  listen_port: 7878,
  domain_name: "example.com",
  auth_secret: "123456789",
  nonce_secret: "123456789"

config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:file, :line]

import_config "#{config_env()}.exs"
