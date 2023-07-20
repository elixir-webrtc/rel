import Config

config :ex_turn,
  public_ip: {127, 0, 0, 1},
  listen_ip: {0, 0, 0, 0},
  listen_port: 7878,
  domain_name: "example.com",
  auth_secret: "123456789",
  nonce_secret: "123456789",
  auth_provider_port: 4000,
  credentials_lifetime: 24 * 60 * 60

config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:listener, :client, :alloc]

import_config "#{config_env()}.exs"
