import Config

config :ex_turn,
  # 1 day in seconds, see https://datatracker.ietf.org/doc/html/draft-uberti-rtcweb-turn-rest-00#section-2.2
  credentials_lifetime: 24 * 60 * 60,
  # 10 minutes in seconds
  default_allocation_lifetime: 10 * 60,
  # 1 hour in seconds 
  max_allocation_lifetime: 60 * 60,
  # 5 minutes in seconds
  permission_lifetime: 60 * 5,
  # 10 minutes in seconds
  channel_lifetime: 60 * 10,
  # 1 hour in nanoseconds, see https://datatracker.ietf.org/doc/html/rfc5766#section-4
  nonce_lifetime: 60 * 60 * 1_000_000_000

config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:listener, :client, :alloc]

import_config "#{config_env()}.exs"
