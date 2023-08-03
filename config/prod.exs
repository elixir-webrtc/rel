import Config

# FIXME: temporary, as `:credentials_lifetime` is a compile time variable atm
config :ex_turn, :credentials_lifetime, 3 * 24 * 24
