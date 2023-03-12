defmodule ExTURN.Utils do
  require Logger

  alias ExStun.Message
  alias ExStun.Message.Type
  alias ExStun.Message.Attribute.{ErrorCode, Nonce, MessageIntegrity, Realm, Username}

  @auth_secret Application.compile_env!(:ex_turn, :auth_secret)

  @spec authenticate(Message.t()) :: {:ok, String.t()} | {:error, Message.t()}
  def authenticate(%Message{} = msg) do
    case MessageIntegrity.get_from_message(msg) do
      nil ->
        Logger.info("No message integrity attribute. Seems like a new allocation.")
        type = %Type{class: :error_response, method: :allocate}

        response =
          Message.new(msg.transaction_id, type, [
            %Nonce{value: "testnonce"},
            %Realm{value: "testrealm"},
            %ErrorCode{code: 401}
          ])

        {:error, response}

      {:ok, %MessageIntegrity{} = attr} ->
        Logger.info("Got message integrity, #{inspect(attr)}")
        {:ok, %Username{value: username}} = Username.get_from_message(msg)
        {:ok, %Realm{value: realm}} = Realm.get_from_message(msg)

        [expiry_time, _name] = String.split(username, ":", parts: 2)

        if String.to_integer(expiry_time) - System.os_time(:second) <= 0 do
          Logger.info("Username expired. Unauthenticated.")
          type = %Type{class: :error_response, method: :allocate}
          response = Message.new(msg.transaction_id, type, [%ErrorCode{code: 401}])
          {:error, response}
        else
          password = :crypto.mac(:hmac, :sha, @auth_secret, username) |> :base64.encode()

          key = username <> ":" <> realm <> ":" <> password
          key = :crypto.hash(:md5, key)
          size = byte_size(msg.raw) - 24
          <<msg_without_integrity::binary-size(size), _rest::binary>> = msg.raw
          mac = :crypto.mac(:hmac, :sha, key, msg_without_integrity)

          if mac == attr.value do
            Logger.info("Request authenticated")
            {:ok, key}
          else
            Logger.info("Bad message integrity")
            type = %Type{class: :error_response, method: :allocate}
            response = Message.new(msg.transaction_id, type, [%ErrorCode{code: 401}])
            {:error, response}
          end
        end
    end
  end

  @spec generate_password(String.t()) :: String.t()
  def generate_password(username) do
    :crypto.mac(:hmac, :sha, @auth_secret, username) |> :base64.encode()
  end
end
