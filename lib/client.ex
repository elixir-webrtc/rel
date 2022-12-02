defmodule ExTURN.Client do
  require Logger

  alias ExStun.Message
  alias ExStun.Message.{Attribute, Type}

  def serve(client) do
    receive do
      {:tcp_closed, ^client} ->
        Logger.info("TCP connection closed. Closing client #{inspect(client)}")

      {:tcp, _port, msg} ->
        with {:ok, msg} <- ExStun.Message.decode(msg) do
          handle_message(msg)
        else
          {:error, reason} ->
            Logger.warn("""
            Couldn't decode STUN message, reason: #{inspect(reason)}, message: #{inspect(msg)}
            """)
        end

        serve(client)
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
    case Attribute.MessageIntegrity.get_from_message(msg) do
      nil -> Logger.info("No message integrity attribute. Seems like a new allocation.")
      attr -> IO.inspect(attr)
    end
  end
end
