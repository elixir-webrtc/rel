defmodule ExTURN.Monitor do
  require Logger

  def start(pid, socket) do
    ref = Process.monitor(pid)

    receive do
      {:DOWN, ^ref, ^pid, _object, _reason} ->
        Logger.info("Closing socket #{inspect(socket)}")
        :gen_udp.close(socket)
    end
  end
end
