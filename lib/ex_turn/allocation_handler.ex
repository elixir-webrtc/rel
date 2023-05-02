defmodule ExTURN.AllocationHandler do
  use GenServer
  require Logger

  alias ExStun.Message
  alias ExStun.Message.Type
  alias ExStun.Message.Attribute.ErrorCode
  alias ExTURN.Utils

  def start_link(turn_socket, alloc_socket, five_tuple) do
    GenServer.start_link(
      __MODULE__,
      [turn_socket: turn_socket, alloc_socket: alloc_socket, five_tuple: five_tuple],
      name: {:via, Registry, {Registry.Allocations, five_tuple}}
    )
  end

  @impl true
  def init(turn_socket: turn_socket, alloc_socket: socket, five_tuple: five_tuple) do
    Logger.info("Starting allocation handler #{inspect(five_tuple)}")

    {:ok,
     %{
       turn_socket: turn_socket,
       socket: socket,
       five_tuple: five_tuple,
       permissions: MapSet.new(),
       channels: %{}
     }}
  end

  @impl true
  def handle_info({:msg, msg}, state) do
    state = handle_msg(msg, state)
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

    :gen_udp.send(state.turn_socket, c_ip, c_port, response)

    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warn("Got unexpected msg: #{inspect(msg)}")
    {:noreply, state}
  end

  defp handle_msg(%Message{type: %Type{class: :request, method: :create_permission}} = msg, state) do
    {c_ip, c_port, _, _, _} = state.five_tuple

    case Utils.authenticate(msg) do
      {:ok, key} ->
        # FIXME handle multiple addresses
        # FIXME assume that address is correct for now
        {:ok, xor_addr} = ExTURN.STUN.Attribute.XORPeerAddress.get_from_message(msg)

        # FIXME setup timer
        state = %{state | permissions: MapSet.put(state.permissions, xor_addr.address)}

        type = %Type{class: :success_response, method: msg.type.method}
        response = Message.new(msg.transaction_id, type, []) |> Message.encode_with_int(key)

        :gen_udp.send(state.turn_socket, c_ip, c_port, response)
        state

      {:error, response} ->
        :gen_udp.send(state.turn_socket, c_ip, c_port, response)
        state
    end
  end

  defp handle_msg(%Message{type: %Type{class: :request, method: :binding}} = msg, state) do
    {c_ip, c_port, _, _, _} = state.five_tuple
    type = %Type{class: :success_response, method: msg.type.method}

    response =
      Message.new(msg.transaction_id, type, [
        %ExStun.Message.Attribute.XORMappedAddress{family: :ipv4, port: c_port, address: c_ip}
      ])
      |> Message.encode()

    :gen_udp.send(state.turn_socket, c_ip, c_port, response)

    state
  end

  defp handle_msg(%Message{type: %Type{class: :indication, method: :send}} = msg, state) do
    {:ok, xor_addr} = ExTURN.STUN.Attribute.XORPeerAddress.get_from_message(msg)
    {:ok, data} = ExTURN.STUN.Attribute.Data.get_from_message(msg)

    :gen_udp.send(state.socket, xor_addr.address, xor_addr.port, data.value.value)

    state
  end

  defp handle_msg(%Message{type: %Type{class: :request, method: :channel_bind}} = msg, state) do
    {c_ip, c_port, _, _, _} = state.five_tuple

    case Utils.authenticate(msg) do
      {:ok, key} ->
        {:ok, channel_num} = ExTURN.STUN.Attribute.ChannelNumber.get_from_message(msg)
        {:ok, xor_addr} = ExTURN.STUN.Attribute.XORPeerAddress.get_from_message(msg)

        {response, state} =
          if xor_addr.family != :ipv4 do
            type = %Type{class: :error_response, method: msg.type.method}

            msg =
              Message.new(msg.transaction_id, type, [%ErrorCode{code: 443}]) |> Message.encode()

            {msg, state}
          else
            state = put_in(state, [:channels, channel_num.number], xor_addr)
            Logger.warn("#{inspect(channel_num)}, #{inspect(state)}")
            type = %Type{class: :success_response, method: msg.type.method}
            msg = Message.new(msg.transaction_id, type, []) |> Message.encode_with_int(key)
            {msg, state}
          end

        :gen_udp.send(state.turn_socket, c_ip, c_port, response)

        state

      {:error, response} ->
        :gen_udp.send(state.turn_socket, c_ip, c_port, response)
        state
    end
  end

  defp handle_msg(<<channel_num::16, _len::16, data::binary>>, state)
       when channel_num in [0x4000, 0x4FFF] do
    xor_addr = Map.fetch!(state.channels, channel_num)
    :gen_udp.send(state.socket, xor_addr.address, xor_addr.port, data)
    state
  end

  # defp handle_msg(<<channel_num::16, len::16, data::binary>>, state) do

  # end

  defp handle_msg(msg, state) do
    Logger.warn("Got unexpected TURN message: #{inspect(msg, limit: :infinity)}")
    state
  end
end
