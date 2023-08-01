import Config

defmodule ConfigParser do
  def parse_ip_address(ip) do
    case ip |> to_charlist() |> :inet.parse_address() do
      {:ok, parsed_ip} ->
        parsed_ip

      _other ->
        raise("""
        Bad IP format. Expected IP address, got: \
        #{inspect(ip)}
        """)
    end
  end

  def parse_port(port) do
    case Integer.parse(port, 10) do
      {val, _rem} when val in 0..49_151 ->
        val

      _other ->
        raise("""
        Bad PORT format. Expected port number, got: \
        #{inspect(port)}
        """)
    end
  end
end

use_tls? = System.get_env("AUTH_PROVIDER_USE_TLS") not in ["0", "false", nil]
keyfile = System.get_env("KEY_FILE_PATH")
certfile = System.get_env("CERT_FILE_PATH")

if use_tls? and (is_nil(keyfile) or is_nil(certfile)) do
  raise "Both KEY_FILE_PATH and CERT_FILE_PATH must be set is TLS is used"
end

config :ex_turn,
  relay_ip: System.get_env("RELAY_IP", "127.0.0.1") |> ConfigParser.parse_ip_address(),
  listen_ip: System.get_env("LISTEN_IP", "127.0.0.1") |> ConfigParser.parse_ip_address(),
  listen_port: System.get_env("UDP_LISTEN_PORT", "3478") |> ConfigParser.parse_port(),
  auth_provider_ip: System.get_env("AUTH_PROVIDER_IP", "127.0.0.1") |> ConfigParser.parse_ip_address(),
  auth_provider_port: System.get_env("AUTH_PROVIDER_PORT", "4000") |> ConfigParser.parse_port(),
  domain_name: System.get_env("DOMAIN_NAME", "example.com"),
  auth_provider_use_tls?: use_tls?,
  keyfile: keyfile,
  certfile: certfile,
  auth_secret: :crypto.strong_rand_bytes(64),
  nonce_secret: :crypto.strong_rand_bytes(64)
