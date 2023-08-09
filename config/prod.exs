import Config

# FIXME: temporary, as `:credentials_lifetime` is a compile time variable atm
config :rel, :credentials_lifetime, 3 * 24 * 24
