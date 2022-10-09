defmodule ExTURN.Client do
  require Logger

  def serve(client) do
    receive do
      {:tcp_closed, ^client} ->
        Logger.info("TCP connection closed. Closing client #{inspect(client)}")

      msg ->
        IO.inspect(msg)
        serve(client)
    end
  end
end
