defmodule Rel.AllocationHandler do
  @moduledoc false
  use GenServer, restart: :transient

  require Logger

  alias ExSTUN.Message
  alias ExSTUN.Message.Type

  alias Rel.Auth
  alias Rel.Attribute.{ChannelNumber, Data, Lifetime, XORPeerAddress}
  alias Rel.Utils

  @type five_tuple() ::
          {:inet.ip_address(), :inet.port_number(), :inet.ip_address(), :inet.port_number(), :udp}

  @typedoc """
  Allocation handler init args.

  * `t_id` is the origin allocation request transaction id
  * `response` is the origin response for the origin alloaction request
  """
  @type alloc_args() :: [
          five_tuple: five_tuple(),
          alloc_socket: :gen_udp.socket(),
          turn_socket: :gen_udp.socket(),
          username: binary(),
          time_to_expiry: integer(),
          t_id: integer(),
          response: binary()
        ]

  @permission_lifetime Application.compile_env!(:rel, :permission_lifetime)
  @channel_lifetime Application.compile_env!(:rel, :channel_lifetime)

  @spec start_link(alloc_args()) :: GenServer.on_start()
  def start_link(args) do
    alloc_socket = Keyword.fetch!(args, :alloc_socket)
    five_tuple = Keyword.fetch!(args, :five_tuple)
    t_id = Keyword.fetch!(args, :t_id)
    response = Keyword.fetch!(args, :response)

    {:ok, {_alloc_ip, alloc_port}} = :inet.sockname(alloc_socket)

    alloc_origin_state = %{alloc_port: alloc_port, t_id: t_id, response: response}

    GenServer.start_link(
      __MODULE__,
      args,
      name: {:via, Registry, {Registry.Allocations, five_tuple, alloc_origin_state}}
    )
  end

  @spec process_stun_message(GenServer.server(), term()) :: :ok
  def process_stun_message(allocation, msg) do
    GenServer.cast(allocation, {:stun_message, msg})
  end

  @spec process_channel_message(GenServer.server(), term()) :: :ok
  def process_channel_message(allocation, msg) when is_binary(msg) do
    GenServer.cast(allocation, {:channel_message, msg})
  end

  @impl true
  def init(args) do
    five_tuple = Keyword.fetch!(args, :five_tuple)
    alloc_socket = Keyword.fetch!(args, :alloc_socket)
    turn_socket = Keyword.fetch!(args, :turn_socket)
    username = Keyword.fetch!(args, :username)
    time_to_expiry = Keyword.fetch!(args, :time_to_expiry)

    {c_ip, c_port, s_ip, s_port, _transport} = five_tuple
    alloc_id = "(#{:inet.ntoa(c_ip)}:#{c_port}, #{:inet.ntoa(s_ip)}:#{s_port}, UDP)"
    Logger.metadata(alloc: alloc_id)
    Logger.info("Starting new allocation handler")

    :telemetry.execute([:allocations], %{created: 1, expired: 0})

    Process.send_after(self(), :check_expiration, time_to_expiry * 1000)

    {:ok,
     %{
       alloc_id: alloc_id,
       turn_socket: turn_socket,
       socket: alloc_socket,
       five_tuple: five_tuple,
       username: username,
       expiry_timestamp: System.os_time(:second) + time_to_expiry,
       permissions: %{},
       chann_to_time: %{},
       chann_to_addr: %{},
       addr_to_chann: %{}
     }}
  end

  @impl true
  def handle_cast({:stun_message, msg}, state) do
    case handle_message(msg, state) do
      {:ok, state} -> {:noreply, state}
      {:allocation_expired, state} -> {:stop, {:shutdown, :allocation_expired}, state}
    end
  end

  @impl true
  def handle_cast(
        {:channel_message, <<number::16, len::16, data::binary-size(len), _padding::binary>>},
        state
      ) do
    case Map.fetch(state.chann_to_addr, number) do
      {:ok, addr} ->
        :ok = :gen_udp.send(state.socket, addr, data)

      :error ->
        nil
    end

    {:noreply, state}
  end

  @impl true
  def handle_info({:udp, _socket, ip_addr, port, packet}, state) do
    len = byte_size(packet)

    :telemetry.execute([:allocations, :peer], %{inbound: len})

    if Map.has_key?(state.permissions, ip_addr) do
      {c_ip, c_port, _, _, _} = state.five_tuple

      case Map.fetch(state.addr_to_chann, {ip_addr, port}) do
        {:ok, number} ->
          channel_data = <<number::16, len::16, packet::binary>>

          :ok =
            :socket.sendto(state.turn_socket, channel_data, %{
              family: :inet,
              addr: c_ip,
              port: c_port
            })

        :error ->
          xor_addr = %XORPeerAddress{port: port, address: ip_addr}
          data = %Data{value: packet}

          response =
            %Type{class: :indication, method: :data}
            |> Message.new([xor_addr, data])
            |> Message.encode()

          :ok =
            :socket.sendto(state.turn_socket, response, %{family: :inet, addr: c_ip, port: c_port})
      end

      {:noreply, state}
    else
      Logger.warning(
        "Received UDP datagram from #{:inet.ntoa(ip_addr)}, but no permission was created"
      )

      {:noreply, state}
    end
  end

  @impl true
  def handle_info(:check_expiration, state) do
    if System.os_time(:second) >= state.expiry_timestamp do
      Logger.info("Allocation expired, shutting down allocation handler")
      {:stop, {:shutdown, :allocation_expired}, state}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_info({:check_permission, addr}, state) do
    if System.os_time(:second) >= state.permissions[addr] do
      Logger.info("Permission for #{:inet.ntoa(addr)} expired")
      {_val, state} = pop_in(state.permissions[addr])
      {:noreply, state}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_info({:check_channel, number}, state) do
    if System.os_time(:second) >= state.chann_to_time[number] do
      {ip_addr, port} = addr = state.chann_to_addr[number]
      Logger.info("Channel binding #{number} <-> #{:inet.ntoa(ip_addr)}:#{port} expired")
      {_val, state} = pop_in(state.chann_to_addr[number])
      {_val, state} = pop_in(state.addr_to_chann[addr])
      {_val, state} = pop_in(state.chann_to_time[number])

      {:noreply, state}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_info(msg, state) do
    Logger.warning("Got unexpected OTP message: #{inspect(msg)}")
    {:noreply, state}
  end

  @impl true
  def terminate(reason, _state) do
    :telemetry.execute([:allocations], %{created: 0, expired: 1})
    Logger.info("Allocation handler stopped with reason: #{inspect(reason)}")
  end

  defp handle_message(%Message{type: %Type{class: :request, method: :refresh}} = msg, state) do
    Logger.info("Received 'refresh' request")
    {c_ip, c_port, _, _, _} = state.five_tuple

    with {:ok, key} <- Auth.authenticate(msg, username: state.username),
         {:ok, time_to_expiry} <- Utils.get_lifetime(msg) do
      type = %Type{class: :success_response, method: :refresh}

      response =
        msg.transaction_id
        |> Message.new(type, [%Lifetime{lifetime: time_to_expiry}])
        |> Message.with_integrity(key)
        |> Message.encode()

      :ok =
        :socket.sendto(state.turn_socket, response, %{family: :inet, addr: c_ip, port: c_port})

      if time_to_expiry == 0 do
        Logger.info("Allocation deleted with LIFETIME=0 refresh request")
        {:allocation_expired, state}
      else
        state = %{state | expiry_timestamp: System.os_time(:second) + time_to_expiry}
        Process.send_after(self(), :check_expiration, time_to_expiry * 1000)

        Logger.info("Succesfully refreshed allocation, new 'time-to-expiry': #{time_to_expiry}")

        {:ok, state}
      end
    else
      {:error, reason} ->
        {response, log_msg} = Utils.build_error(reason, msg.transaction_id, msg.type.method)
        Logger.warning(log_msg)

        :ok =
          :socket.sendto(state.turn_socket, response, %{family: :inet, addr: c_ip, port: c_port})

        {:ok, state}
    end
  end

  defp handle_message(
         %Message{type: %Type{class: :request, method: :create_permission}} = msg,
         state
       ) do
    Logger.info("Received 'create_permission' request")
    {c_ip, c_port, _, _, _} = state.five_tuple

    with {:ok, key} <- Auth.authenticate(msg, username: state.username),
         {:ok, state} <- install_of_refresh_permission(msg, state) do
      type = %Type{class: :success_response, method: msg.type.method}

      response =
        msg.transaction_id
        |> Message.new(type, [])
        |> Message.with_integrity(key)
        |> Message.encode()

      :ok =
        :socket.sendto(state.turn_socket, response, %{family: :inet, addr: c_ip, port: c_port})

      {:ok, state}
    else
      {:error, reason} ->
        {response, log_msg} = Utils.build_error(reason, msg.transaction_id, msg.type.method)
        Logger.warning(log_msg)

        :ok =
          :socket.sendto(state.turn_socket, response, %{family: :inet, addr: c_ip, port: c_port})

        {:ok, state}
    end
  end

  defp handle_message(%Message{type: %Type{class: :indication, method: :send}} = msg, state) do
    with {:ok, %XORPeerAddress{address: ip_addr, port: port}} <- get_xor_peer_address(msg),
         {:ok, %Data{value: data}} <- get_data(msg),
         true <- Map.has_key?(state.permissions, ip_addr) do
      # TODO: dont fragment attribute
      :ok = :gen_udp.send(state.socket, ip_addr, port, data)
      {:ok, state}
    else
      false ->
        {:ok, %XORPeerAddress{address: addr}} = get_xor_peer_address(msg)

        Logger.warning(
          "Error while processing 'indication' request, no permission for #{:inet.ntoa(addr)}"
        )

        {:ok, state}

      {:error, reason} ->
        {_response, log_msg} = Utils.build_error(reason, msg.transaction_id, msg.type.method)
        Logger.warning("Error while processing 'indication' request. " <> log_msg)
        # no response here, messages are silently discarded
        {:ok, state}
    end
  end

  defp handle_message(%Message{type: %Type{class: :request, method: :channel_bind}} = msg, state) do
    Logger.info("Received 'channel_bind' request")
    {c_ip, c_port, _, _, _} = state.five_tuple

    with {:ok, key} <- Auth.authenticate(msg, username: state.username),
         {:ok, %XORPeerAddress{address: ip_addr, port: port}} <- get_xor_peer_address(msg),
         {:ok, %ChannelNumber{number: number}} <- get_channel_number(msg),
         {:ok, state} <- assign_channel(ip_addr, port, number, state) do
      type = %Type{class: :success_response, method: msg.type.method}

      {:ok, state} = install_of_refresh_permission(msg, state, limit: 1)

      response =
        msg.transaction_id
        |> Message.new(type, [])
        |> Message.with_integrity(key)
        |> Message.encode()

      :ok =
        :socket.sendto(state.turn_socket, response, %{family: :inet, addr: c_ip, port: c_port})

      Logger.info("Succesfully bound channel #{number} to address #{:inet.ntoa(ip_addr)}:#{port}")

      {:ok, state}
    else
      {:error, reason} ->
        {response, log_msg} = Utils.build_error(reason, msg.transaction_id, msg.type.method)
        Logger.warning(log_msg)

        :ok =
          :socket.sendto(state.turn_socket, response, %{family: :inet, addr: c_ip, port: c_port})

        {:ok, state}
    end
  end

  defp handle_message(msg, state) do
    Logger.warning("Got unexpected TURN message: #{inspect(msg, limit: :infinity)}")
    {:ok, state}
  end

  defp install_of_refresh_permission(msg, state, opts \\ []) do
    case Message.get_all_attributes(msg, XORPeerAddress) do
      nil ->
        {:error, :no_xor_peer_address_attribute}

      {:error, _reason} ->
        {:error, :invalid_xor_peer_address}

      {:ok, addrs} ->
        limit = Keyword.get(opts, :limit)
        addrs = if(limit != nil, do: Enum.take(addrs, limit), else: addrs)

        permissions =
          Map.new(addrs, fn %XORPeerAddress{address: addr} ->
            Process.send_after(self(), {:check_permission, addr}, @permission_lifetime * 1000)
            Logger.info("Succesfully created or refreshed permission for #{:inet.ntoa(addr)}")
            {addr, System.os_time(:second) + @permission_lifetime}
          end)

        state = update_in(state.permissions, &Map.merge(&1, permissions))
        {:ok, state}
    end
  end

  defp get_xor_peer_address(msg) do
    case Message.get_attribute(msg, XORPeerAddress) do
      {:ok, _attr} = resp -> resp
      nil -> {:error, :no_xor_peer_address_attribute}
      {:error, _reason} -> {:error, :invalid_xor_peer_address}
    end
  end

  defp get_data(msg) do
    case Message.get_attribute(msg, Data) do
      {:ok, _attr} = resp -> resp
      nil -> {:error, :no_data_attribute}
      {:error, _reason} -> {:error, :invalid_data}
    end
  end

  defp get_channel_number(msg) do
    case Message.get_attribute(msg, ChannelNumber) do
      {:ok, _attr} = resp -> resp
      nil -> {:error, :no_channel_number_attribute}
      {:error, _reason} -> {:error, :invalid_channel_number}
    end
  end

  defp assign_channel(ip_addr, port, number, state) do
    addr = {ip_addr, port}
    cur_addr = Map.get(state.chann_to_addr, number)
    cur_number = Map.get(state.addr_to_chann, addr)

    with true <- number in 0x4000..0x7FFE,
         {:num, true} <- {:num, is_nil(cur_addr) or cur_addr == addr},
         {:addr, true} <- {:addr, is_nil(cur_number) or cur_number == number} do
      state =
        state
        |> put_in([:chann_to_addr, number], addr)
        |> put_in([:addr_to_chann, addr], number)
        |> put_in([:chann_to_time, number], System.os_time(:second) + @channel_lifetime)

      Process.send_after(self(), {:check_channel, number}, @channel_lifetime)

      {:ok, state}
    else
      false -> {:error, :channel_number_out_of_range}
      {:num, false} -> {:error, :channel_number_bound}
      {:addr, false} -> {:error, :addr_bound_to_channel}
    end
  end
end
