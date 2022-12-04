defmodule ExTURN.ClientHandler do
  require Logger

  alias ExStun.Message
  alias ExStun.Message.Type

  alias ExTURN.Utils

  def serve(socket) do
    receive do
      {:tcp_closed, ^socket} ->
        Logger.info("TCP connection closed. Closing client #{inspect(socket)}")

      {:tcp, _port, msg} ->
        with {:ok, msg} <- ExStun.Message.decode(msg) do
          response = handle_message(msg)
          response = Message.encode(response)
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
    case Utils.authenticate(msg) do
      :ok -> ""
      {:error, response} -> response
    end
  end

  defp handle_unknown_message(msg) do
    Logger.warn("Unknown message type, #{inspect(msg)}")
  end
end
