defmodule ExTURN.AllocationHandler do
  use GenServer
  require Logger

  def start_link(socket, five_tuple) do
    GenServer.start_link(
      __MODULE__,
      [socket: socket, five_tuple: five_tuple],
      name: {:via, Registry, {Registry.Allocations, five_tuple}}
    )
  end

  @impl true
  def init(socket: socket, five_tuple: five_tuple) do
    Logger.info("Starting allocation handler #{inspect(five_tuple)}")
    {:ok, %{socket: socket, five_tuple: five_tuple}}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.info("AllocationHandler got message: #{inspect(msg)}")
    {:noreply, state}
  end
end
