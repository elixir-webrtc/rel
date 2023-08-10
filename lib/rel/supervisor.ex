defmodule Rel.Supervisor do
  @moduledoc false
  use Supervisor

  @spec start_link(any()) :: Supervisor.on_start()
  def start_link(_arg) do
    Supervisor.start_link(__MODULE__, nil, name: __MODULE__)
  end

  @impl true
  def init(_arg) do
    listen_ip = Application.fetch_env!(:rel, :listen_ip)
    listen_port = Application.fetch_env!(:rel, :listen_port)

    children = [
      {DynamicSupervisor, strategy: :one_for_one, name: Rel.AllocationSupervisor},
      {Registry, keys: :unique, name: Registry.Allocations},
      {Rel.Listener, [listen_ip, listen_port]}
    ]

    Supervisor.init(children, strategy: :one_for_all)
  end
end
