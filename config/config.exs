import Config

config :ex_turn,
  ip: {127, 0, 0, 1},
  port: 7878,
  auth_secret: "123456789"

config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:file, :line]
