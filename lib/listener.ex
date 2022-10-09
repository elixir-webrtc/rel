defmodule ExTURN.Listener do
  require Logger

  def listen(ip, port, :tcp = proto) do
    Logger.info("Starting new listener ip: #{inspect(ip)}, port: #{port}, proto: #{proto}")
    {:ok, socket} = :gen_tcp.listen(port, [:binary, ifaddr: ip])
    accept_loop(socket)
  end

  defp accept_loop(socket) do
    {:ok, client} = :gen_tcp.accept(socket)
    Logger.info("New incoming connection")

    {:ok, pid} =
      Task.Supervisor.start_child(ExTURN.ClientSupervisor, ExTURN.Client, :serve, [client])

    :ok = :gen_tcp.controlling_process(client, pid)
    accept_loop(socket)
  end
end
