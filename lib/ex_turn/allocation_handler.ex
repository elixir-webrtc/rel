defmodule ExTURN.AllocationHandler do
  @moduledoc false
  use GenServer
  require Logger

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{ErrorCode, XORMappedAddress}

  alias ExTURN.Auth
  alias ExTURN.Attribute.{ChannelNumber, Data, XORPeerAddress}

  def start_link(turn_socket, alloc_socket, five_tuple, username) do
    {:ok, {_alloc_ip, alloc_port}} = :inet.sockname(alloc_socket)

    GenServer.start_link(
      __MODULE__,
      [
        turn_socket: turn_socket,
        alloc_socket: alloc_socket,
        five_tuple: five_tuple,
        username: username
      ],
      name: {:via, Registry, {Registry.Allocations, five_tuple, alloc_port}}
    )
  end

  @impl true
  def init(
        turn_socket: turn_socket,
        alloc_socket: socket,
        five_tuple: five_tuple,
        username: username
      ) do
    Logger.info("Starting allocation handler #{inspect(five_tuple)}")

    Process.send_after(self(), :measure_bitrate, 1000)

    {:ok,
     %{
       alloc_id: "#{inspect(five_tuple)}",
       turn_socket: turn_socket,
       socket: socket,
       five_tuple: five_tuple,
       username: username,
       permissions: MapSet.new(),
       channels: %{},

       # stats
       # bytes sent by the client
       out_bytes: 0,
       # bytes sent to the client
       in_bytes: 0,
       last_check: System.monotonic_time(:second)
     }}
  end

  @impl true
  def handle_info({:msg, msg}, state) do
    state = handle_msg(msg, state)
    {:noreply, state}
  end

  @impl true
  def handle_info({:udp, _socket, ip, port, packet}, state) do
    xor_addr = %XORPeerAddress{port: port, address: ip}
    data = %Data{value: packet}

    type = %Type{class: :indication, method: :data}
    response = Message.new(type, [xor_addr, data]) |> Message.encode()

    {c_ip, c_port, _, _, _} = state.five_tuple

    :gen_udp.send(state.turn_socket, c_ip, c_port, response)

    state = %{state | in_bytes: state.in_bytes + byte_size(packet)}

    {:noreply, state}
  end

  @impl true
  def handle_info(:measure_bitrate, state) do
    now = System.monotonic_time(:second)

    in_bitrate = state.in_bytes / (now - state.last_check)
    out_bitrate = state.out_bytes / (now - state.last_check)

    :telemetry.execute([:allocation], %{in_bitrate: in_bitrate, out_bitrate: out_bitrate}, %{
      allocation_id: state.alloc_id
    })

    state = %{state | in_bytes: 0, out_bytes: 0, last_check: now}

    Process.send_after(self(), :measure_bitrate, 1000)

    {:noreply, state}
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warn("Got unexpected msg: #{inspect(msg)}")
    {:noreply, state}
  end

  defp handle_msg(%Message{type: %Type{class: :request, method: :create_permission}} = msg, state) do
    {c_ip, c_port, _, _, _} = state.five_tuple

    case Auth.authenticate(msg, username: state.username) do
      {:ok, key} ->
        # FIXME handle multiple addresses
        # FIXME assume that address is correct for now
        {:ok, xor_addr} = Message.get_attribute(msg, XORPeerAddress)

        # FIXME setup timer
        state = %{state | permissions: MapSet.put(state.permissions, xor_addr.address)}

        type = %Type{class: :success_response, method: msg.type.method}

        response =
          msg.transaction_id
          |> Message.new(type, [])
          |> Message.with_integrity(key)
          |> Message.encode()

        :gen_udp.send(state.turn_socket, c_ip, c_port, response)
        state

      {:error, response} ->
        :gen_udp.send(state.turn_socket, c_ip, c_port, Message.encode(response))
        state
    end
  end

  defp handle_msg(%Message{type: %Type{class: :request, method: :binding}} = msg, state) do
    {c_ip, c_port, _, _, _} = state.five_tuple
    type = %Type{class: :success_response, method: msg.type.method}

    response =
      Message.new(msg.transaction_id, type, [
        %XORMappedAddress{port: c_port, address: c_ip}
      ])
      |> Message.encode()

    :gen_udp.send(state.turn_socket, c_ip, c_port, response)

    state
  end

  defp handle_msg(%Message{type: %Type{class: :indication, method: :send}} = msg, state) do
    {:ok, xor_addr} = Message.get_attribute(msg, XORPeerAddress)
    {:ok, data} = Message.get_attribute(msg, Data)

    :gen_udp.send(state.socket, xor_addr.address, xor_addr.port, data.value)

    %{state | out_bytes: state.out_bytes + byte_size(data.value)}
  end

  defp handle_msg(%Message{type: %Type{class: :request, method: :channel_bind}} = msg, state) do
    {c_ip, c_port, _, _, _} = state.five_tuple

    case Auth.authenticate(msg, username: state.username) do
      {:ok, key} ->
        {:ok, channel_num} = Message.get_attribute(msg, ChannelNumber)
        {:ok, xor_addr} = Message.get_attribute(msg, XORPeerAddress)

        {response, state} =
          if family(xor_addr.address) != :ipv4 do
            type = %Type{class: :error_response, method: msg.type.method}

            msg =
              Message.new(msg.transaction_id, type, [%ErrorCode{code: 443}]) |> Message.encode()

            {msg, state}
          else
            state = put_in(state, [:channels, channel_num.number], xor_addr)
            type = %Type{class: :success_response, method: msg.type.method}

            msg =
              msg.transaction_id
              |> Message.new(type, [])
              |> Message.with_integrity(key)
              |> Message.encode()

            {msg, state}
          end

        :gen_udp.send(state.turn_socket, c_ip, c_port, response)

        state

      {:error, response} ->
        :gen_udp.send(state.turn_socket, c_ip, c_port, Message.encode(response))
        state
    end
  end

  defp handle_msg(<<channel_num::16, _len::16, data::binary>>, state)
       when channel_num in [0x4000, 0x4FFF] do
    xor_addr = Map.fetch!(state.channels, channel_num)
    :gen_udp.send(state.socket, xor_addr.address, xor_addr.port, data)

    %{state | out_bytes: state.out_bytes + byte_size(data)}
  end

  # defp handle_msg(<<channel_num::16, len::16, data::binary>>, state) do

  # end

  defp handle_msg(msg, state) do
    Logger.warn("Got unexpected TURN message: #{inspect(msg, limit: :infinity)}")
    state
  end

  defp family({_, _, _, _}), do: :ipv4
  defp family({_, _, _, _, _, _, _, _}), do: :ipv6
end
