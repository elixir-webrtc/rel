defmodule ExTURN.App do
  use Application

  require Logger

  def start(_, _) do
    Logger.info("Starting ExTURN")

    listen_ip = Application.get_env(:ex_turn, :ip, {127, 0, 0, 1})
    listen_port = Application.get_env(:ex_turn, :port, 7878)

    listener_child_spec = %{
      id: ExTURN.Listener,
      start: {Task, :start, [ExTURN.Listener, :listen, [listen_ip, listen_port]]}
    }

    children = [
      {DynamicSupervisor, strategy: :one_for_one, name: ExTURN.AllocationSupervisor},
      {Registry, keys: :unique, name: Registry.Allocations},
      listener_child_spec
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
