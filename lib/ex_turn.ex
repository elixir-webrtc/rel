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
    config = File.read!("config.toml")
    {:ok, %{"ip" => _ip, "port" => port}} = Toml.decode(config)
    # {:ok, ip} = :inet.parse_ipv4_address(ip)
    ip = {127, 0, 0, 1}
    do_add_listener(ip, port, :tcp)
    {:ok, %{}}
  end

  @impl true
  def handle_call({:add_listener, ip, port, proto}, _from, state) do
    add_listener(ip, port, proto)
    {:reply, :ok, state}
  end

  defp do_add_listener(ip, port, proto) do
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
  end
end
