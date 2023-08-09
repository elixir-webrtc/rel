defmodule Rel.Monitor do
  @moduledoc false
  require Logger

  @spec start(pid(), :inet.socket()) :: :ok
  def start(pid, socket) do
    ref = Process.monitor(pid)

    receive do
      {:DOWN, ^ref, ^pid, _object, _reason} ->
        Logger.info("Closing socket #{inspect(socket)}")
        :ok = :gen_udp.close(socket)
    end
  end
end
