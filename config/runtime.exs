import Config

require Logger

defmodule ConfigUtils do
  @truthy_values ["true", "t", "1"]

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
      {val, _rem} when val in 0..65_535 ->
        val

      _other ->
        raise("""
        Bad PORT format. Expected port number, got: \
        #{inspect(port)}
        """)
    end
  end

  def is_truthy?(env_var) do
    String.downcase(env_var) in @truthy_values
  end

  def guess_external_ip(listen_ip)
      when listen_ip not in [{0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}],
      do: listen_ip

  def guess_external_ip(_listen_ip) do
    with {:ok, opts} <- :inet.getifaddrs(),
         addrs <- Enum.map(opts, fn {_intf, opt} -> opt end),
         addrs <- Enum.filter(addrs, &is_valid?(&1)),
         addrs <- Enum.flat_map(addrs, &Keyword.get_values(&1, :addr)),
         addrs <- Enum.filter(addrs, &(not link_local?(&1) and not any?(&1))),
         false <- Enum.empty?(addrs) do
      case Enum.find(addrs, &(not private?(&1))) do
        nil -> hd(addrs)
        other -> other
      end
    else
      _other ->
        raise "Cannot find an external IP address, pass one explicitely via EXTERNAL_IP env variable"
    end
  end

  defp is_valid?(inter) do
    flags = Keyword.get(inter, :flags)
    :up in flags and :loopback not in flags
  end

  defp link_local?({169, 254, _, _}), do: true
  defp link_local?({0xFE80, _, _, _, _, _, _, _}), do: true
  defp link_local?(_other), do: false

  defp any?({0, 0, 0, 0}), do: true
  defp any?({0, 0, 0, 0, 0, 0, 0, 0}), do: true
  defp any?(_other), do: false

  defp private?({10, _, _, _}), do: true
  defp private?({192, 168, _, _}), do: true
  defp private?({172, b, _, _}) when b in 16..31, do: true
  defp private?({0xFC00, 0, 0, 0, 0, 0, 0, 0}), do: true
  defp private?(_other), do: false
end

# HTTPS for AuthProvider
auth_use_tls? = System.get_env("AUTH_USE_TLS", "false") |> ConfigUtils.is_truthy?()
auth_keyfile = System.get_env("AUTH_KEYFILE")
auth_certfile = System.get_env("AUTH_CERTFILE")

if auth_use_tls? and (is_nil(auth_keyfile) or is_nil(auth_certfile)) do
  raise "Both KEY_FILE_PATH and CERT_FILE_PATH must be set is TLS is used"
end

# IP addresses for TURN
listen_ip = System.get_env("LISTEN_IP", "0.0.0.0") |> ConfigUtils.parse_ip_address()

external_listen_ip =
  case System.fetch_env("EXTERNAL_LISTEN_IP") do
    {:ok, addr} -> ConfitUtils.parse_ip_address(addr)
    :error -> ConfigUtils.guess_external_ip(listen_ip)
  end

relay_ip =
  case System.fetch_env("RELAY_IP") do
    {:ok, addr} -> ConfigUtils.parse_ip_address(addr)
    :error -> listen_ip
  end

external_relay_ip =
  case System.fetch_env("EXTERNAL_RELAY_IP") do
    {:ok, addr} -> ConfigUtils.parse_ip_address(addr)
    :error -> external_listen_ip
  end

relay_port_start = System.get_env("RELAY_PORT_START", "49152") |> ConfigUtils.parse_port()
relay_port_end = System.get_env("RELAY_PORT_END", "65535") |> ConfigUtils.parse_port()

if relay_port_start > relay_port_end,
  do: raise("RELAY_PORT_END must be greater or equal to RELAY_PORT_END")

listener_count =
  case System.fetch_env("LISTENER_COUNT") do
    {:ok, count} ->
      count = String.to_integer(count)
      if count <= 0, do: raise("LISTENER_COUNT must be greater than 0")
      count

    :error ->
      System.schedulers_online()
  end

# AuthProvider/credentials configuration
config :rel,
  auth_ip: System.get_env("AUTH_IP", "127.0.0.1") |> ConfigUtils.parse_ip_address(),
  auth_port: System.get_env("AUTH_PORT", "4000") |> ConfigUtils.parse_port(),
  auth_allow_cors?: System.get_env("AUTH_ALLOW_CORS", "false") |> ConfigUtils.is_truthy?(),
  auth_use_tls?: auth_use_tls?,
  auth_keyfile: auth_keyfile,
  auth_certfile: auth_certfile

# TURN server configuration
config :rel,
  listen_ip: listen_ip,
  external_listen_ip: external_listen_ip,
  relay_ip: relay_ip,
  external_relay_ip: external_relay_ip,
  listen_port: System.get_env("LISTEN_PORT", "3478") |> ConfigUtils.parse_port(),
  realm: System.get_env("REALM", "example.com"),
  relay_port_start: relay_port_start,
  relay_port_end: relay_port_end

# Metrics endpoint configuration
config :rel,
  metrics_ip: System.get_env("METRICS_IP", "127.0.0.1") |> ConfigUtils.parse_ip_address(),
  metrics_port: System.get_env("METRICS_PORT", "9568") |> ConfigUtils.parse_port()

# Automatically generated secrets
config :rel,
  auth_secret: :crypto.strong_rand_bytes(64),
  nonce_secret: :crypto.strong_rand_bytes(64)

# Other
config :rel,
  listener_count: listener_count
