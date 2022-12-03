defmodule ExTURN.Client do
  require Logger

  alias ExStun.Message
  alias ExStun.Message.{Attribute, Type}

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
    authenticate(msg)
  end

  defp handle_unknown_message(msg) do
    Logger.warn("Unknown message type, #{inspect(msg)}")
  end

  defp authenticate(%Message{} = msg) do
    # IO.inspect(msg)
    case Attribute.MessageIntegrity.get_from_message(msg) do
      nil ->
        Logger.info("No message integrity attribute. Seems like a new allocation.")
        type = %Type{class: :error_response, method: :allocate}
        response = Message.new(msg.transaction_id, type)
        nonce = %Attribute.Nonce{value: "testnonce"}
        realm = %Attribute.Realm{value: "testrealm"}
        error_code = %Attribute.ErrorCode{code: 401}
        response = Attribute.Nonce.add_to_message(nonce, response)
        response = Attribute.ErrorCode.add_to_message(error_code, response)

        Attribute.Realm.add_to_message(realm, response)
        |> Message.encode()

      {:ok, %Attribute.MessageIntegrity{} = attr} ->
        IO.inspect(msg)
        Logger.info("Got message integrity, #{inspect(attr)}")
        {:ok, %Attribute.Username{value: username}} = Attribute.Username.get_from_message(msg)
        {:ok, %Attribute.Realm{value: realm}} = Attribute.Realm.get_from_message(msg)

        key = username <> ":" <> realm <> ":" <> "xxx"
        key = :crypto.hash(:md5, key)
        size = byte_size(msg.raw) - 24
        <<msg_without_integrity::binary-size(size), _rest::binary>> = msg.raw
        mac = :crypto.mac(:hmac, :sha, key, msg_without_integrity)
        if mac == attr.value do
          Logger.info("Request authenticated")
        else
          Logger.info("Bad message integrity")
        end
        ""
    end
  end
end
