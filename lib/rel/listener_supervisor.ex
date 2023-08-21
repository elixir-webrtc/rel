defmodule Rel.ListenerSupervisor do
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
    listener_count = Application.fetch_env!(:rel, :listener_count)

    children =
      for id <- 1..listener_count do
        Supervisor.child_spec({Rel.Listener, [listen_ip, listen_port, id]},
          id: "listener_#{id}"
        )
      end

    Supervisor.init(children, strategy: :one_for_one)
  end
end
