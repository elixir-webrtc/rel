defmodule ExTURN.Client do
  require Logger

  alias ExStun.Message.Attribute.ExStun.Message.Attribute.Realm
  alias ExStun.Message.Attribute.ExStun.Message.Attribute.MessageIntegrity
  alias ExStun.Message.Attribute.ExStun.Message.Attribute.Nonce
  alias ExStun.Message
  alias ExStun.Message.{Attribute, Type}
  alias ExStun.Message.Attribute.{ErrorCode, Nonce, MessageIntegrity, Realm, Username}

  def serve(socket) do
    receive do
      {:tcp_closed, ^socket} ->
        Logger.info("TCP connection closed. Closing client #{inspect(socket)}")

      {:tcp, _port, msg} ->
        with {:ok, msg} <- ExStun.Message.decode(msg) do
          response = handle_message(msg)
          :gen_tcp.send(socket, response)
        else
          {:error, reason} ->
            Logger.warn("""
            Couldn't decode STUN message, reason: #{inspect(reason)}, message: #{inspect(msg)}
            """)
        end

        serve(socket)
    end
  end

  defp handle_message(%Message{type: type} = msg) do
    case type do
      %Type{class: :request, method: :allocate} ->
        handle_allocate_request(msg)

      _other ->
        handle_unknown_message(msg)
    end
  end

  defp handle_allocate_request(msg) do
    case authenticate(msg) do
      :ok -> ""
      {:error, response} -> response
    end
  end

  defp handle_unknown_message(msg) do
    Logger.warn("Unknown message type, #{inspect(msg)}")
  end

  defp authenticate(%Message{} = msg) do
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
          |> Message.encode()

        {:error, response}

      {:ok, %Attribute.MessageIntegrity{} = attr} ->
        IO.inspect(msg)
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
          :ok
        else
          Logger.info("Bad message integrity")
          type = %Type{class: :error_response, method: :allocate}

          response =
            Message.new(msg.transaction_id, type, [%ErrorCode{code: 401}])
            |> Message.encode()

          {:error, response}
        end
    end
  end
end
