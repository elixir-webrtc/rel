defmodule ExTURN.Auth do
  @moduledoc false
  require Logger

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{ErrorCode, Nonce, MessageIntegrity, Realm, Username}

  @auth_secret Application.compile_env!(:ex_turn, :auth_secret)
  @domain_name Application.compile_env!(:ex_turn, :domain_name)
  @nonce_secret Application.compile_env!(:ex_turn, :nonce_secret)
  # 1 hour in nanoseconds, see https://datatracker.ietf.org/doc/html/rfc5766#section-4
  @nonce_lifetime 60 * 60 * 1_000_000_000
  # 1 day in seconds by default, see https://datatracker.ietf.org/doc/html/draft-uberti-rtcweb-turn-rest-00#section-2.2
  @credentials_lifetime Application.compile_env(:ex_turn, :credentials_lifetime, 24 * 60 * 60)

  @spec authenticate(Message.t(), username: String.t()) :: {:ok, binary()} | {:error, Message.t()}
  def authenticate(%Message{} = msg, opts \\ []) do
    with :ok <- verify_message_integrity(msg),
         {:ok, username, nonce} <- verify_attrs_presence(msg),
         :ok <- verify_username(msg.type.method, username, opts),
         :ok <- verify_nonce(nonce),
         password <- :crypto.mac(:hmac, :sha, @auth_secret, username) |> :base64.encode(),
         {:ok, key} <- Message.authenticate_lt(msg, password) do
      {:ok, key}
    else
      {:error, :no_message_integrity} ->
        Logger.info("No message integrity attribute. Seems like a new allocation.")
        {:error, build_error(msg.transaction_id, msg.type.method, 401, with_attrs?: true)}

      {:error, :attrs_missing} ->
        Logger.info("No username, nonce or realm attribute. Rejecting.")
        {:error, build_error(msg.transaction_id, msg.type.method, 400)}

      {:error, :invalid_timestamp} ->
        Logger.info("Username timestamp expired. Rejecting.")
        {:error, build_error(msg.transaction_id, msg.type.method, 401, with_attrs?: true)}

      {:error, :invalid_username} ->
        Logger.info("Username differs from the one used previously. Rejecting.")
        {:error, build_error(msg.transaction_id, msg.type.method, 401, with_attrs?: true)}

      {:error, :stale_nonce} ->
        Logger.info("Stale nonce. Rejecting.")
        {:error, build_error(msg.transaction_id, msg.type.method, 438, with_attrs?: true)}

      :error ->
        Logger.info("Bad message integrity")
        {:error, build_error(msg.transaction_id, msg.type.method, 401, with_attrs?: true)}
    end
  end

  defp verify_message_integrity(msg) do
    case Message.get_attribute(msg, MessageIntegrity) do
      {:ok, %MessageIntegrity{} = msg_int} ->
        Logger.info("Got message integrity, #{inspect(msg_int)}")
        :ok

      nil ->
        {:error, :no_message_integrity}
    end
  end

  defp verify_attrs_presence(msg) do
    with {:ok, %Username{value: username}} <- Message.get_attribute(msg, Username),
         {:ok, %Realm{value: _realm}} <- Message.get_attribute(msg, Realm),
         {:ok, %Nonce{value: nonce}} <- Message.get_attribute(msg, Nonce) do
      {:ok, username, nonce}
    else
      nil -> {:error, :attrs_missing}
    end
  end

  defp verify_username(:allocate, username, _opts) do
    # authentication method described in https://datatracker.ietf.org/doc/html/draft-uberti-rtcweb-turn-rest-00
    with [expiry_time | _rest] <- String.split(username, ":", parts: 2),
         {expiry_time, _rem} <- Integer.parse(expiry_time, 10),
         false <- expiry_time - System.os_time(:second) <= 0 do
      :ok
    else
      _other -> {:error, :invalid_timestamp}
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

    is_hash_valid? = hash == :crypto.hash(:sha256, "#{timestamp}:#{@nonce_secret}")

    is_stale? =
      String.to_integer(timestamp) + @nonce_lifetime < System.monotonic_time(:nanosecond)

    if is_hash_valid? and not is_stale?, do: :ok, else: {:error, :stale_nonce}
  end

  defp build_nonce() do
    # inspired by https://datatracker.ietf.org/doc/html/rfc7616#section-5.4
    timestamp = System.monotonic_time(:nanosecond)
    hash = :crypto.hash(:sha256, "#{timestamp}:#{@nonce_secret}")
    "#{timestamp} #{hash}" |> :base64.encode()
  end

  defp build_error(t_id, method, code, opts \\ []) do
    with_attrs? = Keyword.get(opts, :with_attrs?, false)
    error_type = %Type{class: :error_response, method: method}

    attrs = [%ErrorCode{code: code}]

    attrs =
      if with_attrs? do
        attrs ++ [%Nonce{value: build_nonce()}, %Realm{value: @domain_name}]
      else
        attrs
      end

    Message.new(t_id, error_type, attrs)
  end

  @spec generate_credentials(String.t() | nil) ::
          {username :: String.t(), password :: String.t(), ttl :: non_neg_integer()}
  def generate_credentials(username \\ nil) do
    timestamp = System.os_time(:second) + @credentials_lifetime

    username = if is_nil(username), do: "#{timestamp}", else: "#{timestamp}:#{username}"
    password = :crypto.mac(:hmac, :sha, @auth_secret, username) |> :base64.encode()

    {username, password, @credentials_lifetime}
  end
end
