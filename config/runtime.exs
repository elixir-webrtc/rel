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
      {val, _rem} when val in 0..49_151 ->
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
use_tls? = System.get_env("AUTH_PROVIDER_USE_TLS", "false") |> ConfigUtils.is_truthy?()
keyfile = System.get_env("KEY_FILE_PATH")
certfile = System.get_env("CERT_FILE_PATH")

if use_tls? and (is_nil(keyfile) or is_nil(certfile)) do
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
  case System.fetch_env("EXTERNAL_LISTEN_IP") do
    {:ok, addr} -> ConfigUtils.parse_ip_address(addr)
    :error -> external_listen_ip
  end

# AuthProvider/credentials configuration
config :rel,
  auth_provider_ip:
    System.get_env("AUTH_PROVIDER_IP", "127.0.0.1") |> ConfigUtils.parse_ip_address(),
  auth_provider_port: System.get_env("AUTH_PROVIDER_PORT", "4000") |> ConfigUtils.parse_port(),
  auth_provider_allow_cors?:
    System.get_env("AUTH_PROVIDER_ALLOW_CORS", "false") |> ConfigUtils.is_truthy?(),
  auth_provider_use_tls?: use_tls?,
  keyfile: keyfile,
  certfile: certfile

# TURN server configuration
config :rel,
  listen_ip: listen_ip,
  external_listen_ip: external_listen_ip,
  relay_ip: relay_ip,
  external_relay_ip: external_relay_ip,
  listen_port: System.get_env("UDP_LISTEN_PORT", "3478") |> ConfigUtils.parse_port(),
  domain_name: System.get_env("DOMAIN_NAME", "example.com")

# Metrics endpoint configuration
config :rel,
  metrics_ip: System.get_env("METRICS_IP", "127.0.0.1") |> ConfigUtils.parse_ip_address(),
  metrics_port: System.get_env("METRICS_PORT", "9568") |> ConfigUtils.parse_port()

# Automatically generated secrets
config :rel,
  auth_secret: :crypto.strong_rand_bytes(64),
  nonce_secret: :crypto.strong_rand_bytes(64)
