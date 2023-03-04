defmodule ExTURN.Utils do
  require Logger

  alias ExStun.Message
  alias ExStun.Message.Type
  alias ExStun.Message.Attribute.{ErrorCode, Nonce, MessageIntegrity, Realm, Username}

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

        key = username <> ":" <> realm <> ":" <> "xxx"
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
