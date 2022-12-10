defmodule ExTURN.App do
  use Application

  require Logger

  def start(_, _) do
    Logger.info("Starting ExTURN")

    children = [
      {Task.Supervisor, name: ExTURN.ListenerSupervisor},
      {DynamicSupervisor, strategy: :one_for_one, name: ExTURN.AllocationSupervisor},
      {Registry, keys: :unique, name: Registry.Allocations},
      ExTURN
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
