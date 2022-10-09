defmodule ExTURN do
  use GenServer

  require Logger

  def start_link(init_arg \\ []) do
    GenServer.start_link(__MODULE__, init_arg, name: __MODULE__)
  end

  def add_listener(ip, port, transport) do
    GenServer.call(__MODULE__, {:add_listener, ip, port, transport})
  end

  # Server API

  @impl true
  def init(_init_arg) do
    {:ok, %{listeners: %{}}}
  end

  @impl true
  def handle_call({:add_listener, ip, port, proto}, _from, state) do
    Task.Supervisor.start_child(
      ExTURN.ListenerSupervisor,
      ExTURN.Listener,
      :listen,
      [
        ip,
        port,
        proto
      ],
      restart: :permanent
    )

    {:reply, :ok, state}
  end
end
