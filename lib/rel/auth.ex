defmodule Rel.Auth do
  @moduledoc false
  require Logger

  alias ExSTUN.Message
  alias ExSTUN.Message.Attribute.{MessageIntegrity, Nonce, Realm, Username}

  @nonce_lifetime Application.compile_env!(:rel, :nonce_lifetime)
  @credentials_lifetime Application.compile_env!(:rel, :credentials_lifetime)

  @spec authenticate(Message.t(), username: String.t()) :: {:ok, binary()} | {:error, atom()}
  def authenticate(%Message{} = msg, opts \\ []) do
    auth_secret = Application.fetch_env!(:rel, :auth_secret)

    with :ok <- verify_message_integrity(msg),
         {:ok, username, nonce} <- verify_attrs_presence(msg),
         :ok <- verify_username(msg.type.method, username, opts),
         :ok <- verify_nonce(nonce),
         password <- :crypto.mac(:hmac, :sha, auth_secret, username) |> :base64.encode(),
         {:ok, key} <- Message.authenticate_lt(msg, password) do
      {:ok, key}
    else
      {:error, _reason} = err -> err
    end
  end

  defp verify_message_integrity(msg) do
    case Message.get_attribute(msg, MessageIntegrity) do
      {:ok, %MessageIntegrity{}} -> :ok
      nil -> {:error, :no_message_integrity}
    end
  end

  defp verify_attrs_presence(msg) do
    with {:ok, %Username{value: username}} <- Message.get_attribute(msg, Username),
         {:ok, %Realm{value: _realm}} <- Message.get_attribute(msg, Realm),
         {:ok, %Nonce{value: nonce}} <- Message.get_attribute(msg, Nonce) do
      {:ok, username, nonce}
    else
      nil -> {:error, :auth_attrs_missing}
    end
  end

  defp verify_username(:allocate, username, _opts) do
    # authentication method described in https://datatracker.ietf.org/doc/html/draft-uberti-rtcweb-turn-rest-00
    with [expiry_time | _rest] <- String.split(username, ":", parts: 2),
         {expiry_time, _rem} <- Integer.parse(expiry_time, 10),
         false <- expiry_time - System.os_time(:second) <= 0 do
      :ok
    else
      _other -> {:error, :invalid_username_timestamp}
    end
  end

  defp verify_username(_method, username, opts) do
    valid_username = Keyword.fetch!(opts, :username)
    if username != valid_username, do: {:error, :invalid_username}, else: :ok
  end

  defp verify_nonce(nonce) do
    [timestamp, hash] =
      nonce
      |> :base64.decode()
      |> String.split(" ", parts: 2)

    nonce_secret = Application.fetch_env!(:rel, :nonce_secret)

    is_hash_valid? = hash == :crypto.hash(:sha256, "#{timestamp}:#{nonce_secret}")

    is_stale? =
      String.to_integer(timestamp) + @nonce_lifetime < System.monotonic_time(:nanosecond)

    if is_hash_valid? and not is_stale?, do: :ok, else: {:error, :stale_nonce}
  end

  @spec generate_credentials(String.t() | nil) ::
          {username :: String.t(), password :: String.t(), ttl :: non_neg_integer()}
  def generate_credentials(username \\ nil) do
    auth_secret = Application.fetch_env!(:rel, :auth_secret)
    timestamp = System.os_time(:second) + @credentials_lifetime

    username = if is_nil(username), do: "#{timestamp}", else: "#{timestamp}:#{username}"
    password = :crypto.mac(:hmac, :sha, auth_secret, username) |> :base64.encode()

    {username, password, @credentials_lifetime}
  end
end
