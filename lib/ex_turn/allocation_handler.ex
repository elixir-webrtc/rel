defmodule ExTURN.AllocationHandler do
  use GenServer
  require Logger

  alias ExStun.Message
  alias ExStun.Message.Type

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
  def handle_info({:msg, msg}, state) do
    handle_msg(msg, state)
    {:noreply, state}
  end

  @impl true
  def handle_info({:udp, _socket, ip, port, packet}, state) do
    packet = IO.iodata_to_binary(packet)
    xor_addr = %ExTURN.STUN.Attribute.XORPeerAddress{family: :ipv4, port: port, address: ip}
    data = %ExTURN.STUN.Attribute.Data{value: packet}

    type = %Type{class: :indication, method: :data}
    response = Message.new(type, [xor_addr, data]) |> Message.encode()

    {c_ip, c_port, _, _, _} = state.five_tuple

    :gen_udp.send(state.socket, c_ip, c_port, response)

    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warn("Got unexpected msg: #{inspect(msg)}")
    {:noreply, state}
  end

  defp handle_msg(%Message{type: %Type{class: :indication, method: :send}} = msg, state) do
    {:ok, xor_addr} = ExTURN.STUN.Attribute.XORPeerAddress.get_from_message(msg)
    {:ok, data} = ExTURN.STUN.Attribute.Data.get_from_message(msg)

    :gen_udp.send(state.socket, xor_addr.address, xor_addr.port, data.value.value)
  end

  defp handle_msg(msg, state) do
    Logger.warn("Got unexpected TURN message: #{inspect(msg, limit: :infinity)}")
    {:noreply, state}
  end
end
