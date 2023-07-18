defmodule ExTURN.Listener do
  @moduledoc false
  require Logger

  alias ExTURN.Attribute.{
    AdditionalAddressFamily,
    EvenPort,
    Lifetime,
    RequestedTransport,
    ReservationToken,
    RequestedAddressFamily,
    XORRelayedAddress
  }

  alias ExTURN.AllocationHandler
  alias ExTURN.Auth
  alias ExTURN.Utils

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{Username, XORMappedAddress}

  @default_alloc_ports MapSet.new(49_152..65_535)
  # TODO: proper lifetime values

  def listen(ip, port) do
    Logger.info("Starting a new listener on #{:inet.ntoa(ip)}:#{port}/udp")

    {:ok, socket} =
      :gen_udp.open(
        port,
        [
          {:inet_backend, :socket},
          {:ifaddr, ip},
          {:active, false},
          {:recbuf, 1024 * 1024},
          :binary
        ]
      )

    spawn(ExTURN.Monitor, :start, [self(), socket])

    recv_loop(socket, %{
      listener_id: "#{inspect(ip)}, #{port}, udp",
      in_bytes: 0,
      last_stats_check: System.monotonic_time(:millisecond),
      next_stats_check: System.monotonic_time(:millisecond) + 1000
    })
  end

  defp recv_loop(socket, state) do
    now = System.monotonic_time(:millisecond)
    rem_timeout = state.next_stats_check - now

    {next_timeout, state} =
      if rem_timeout <= 0 do
        duration = now - state.last_stats_check
        in_bitrate = state.in_bytes / (duration / 1000)

        :telemetry.execute([:listener], %{in_bitrate: in_bitrate}, %{
          listener_id: state.listener_id
        })

        next_stats_check = System.monotonic_time(:millisecond) + 1000
        {1000, %{state | in_bytes: 0, last_stats_check: now, next_stats_check: next_stats_check}}
      else
        {rem_timeout, state}
      end

    case :gen_udp.recv(socket, 0, next_timeout) do
      {:ok, {client_addr, client_port, packet}} ->
        process(socket, client_addr, client_port, packet)
        recv_loop(socket, %{state | in_bytes: state.in_bytes + byte_size(packet)})

      {:error, :timeout} ->
        recv_loop(socket, state)

      {:error, reason} ->
        Logger.error(
          "Couldn't receive from UDP socket #{inspect(socket)}, reason: #{inspect(reason)}"
        )
    end
  end

  defp process(socket, client_ip, client_port, <<first_byte::8, _rest::binary>> = packet) do
    {:ok, {server_ip, server_port}} = :inet.sockname(socket)
    five_tuple = {client_ip, client_port, server_ip, server_port, :udp}

    if first_byte in 0..3 do
      case Message.decode(packet) do
        {:ok, msg} ->
          handle_message(socket, five_tuple, msg)

        {:error, reason} ->
          Logger.warn(
            "Failed to decode STUN packet, reason: #{inspect(reason)}, packet: #{inspect(packet)}"
          )
      end
    else
      handle_message(socket, five_tuple, packet)
    end
  end

  defp handle_message(
         socket,
         {c_ip, c_port, _, _, _} = five_tuple,
         %Message{type: %Type{class: :request, method: method}} = msg
       )
       when method in [:binding, :allocate] do
    response =
      case Auth.authenticate(msg) do
        {:ok, key} ->
          case method do
            :binding -> handle_binding(c_ip, c_port, key, msg)
            :allocate -> handle_allocate(socket, five_tuple, key, msg)
          end

        {:error, response} ->
          response
      end

    :gen_udp.send(socket, c_ip, c_port, Message.encode(response))
  end

  defp handle_message(_socket, five_tuple, msg) do
    case find_alloc(five_tuple) do
      nil ->
        Logger.info("""
        No allocation for five tuple #{inspect(five_tuple)} and this is not an allocate request. \
        Ignoring message: #{inspect(msg)}\
        """)

      # TODO: shouldnt we send "allocation mismatch" here?

      alloc ->
        AllocationHandler.process_message(alloc, msg)
    end
  end

  defp handle_binding(c_ip, c_port, key, msg) do
    Logger.info("Received binding request from #{:inet.ntoa(c_ip)}:#{c_port}")

    type = %Type{class: :success_response, method: :binding}

    msg.transaction_id
    |> Message.new(type, [
      %XORMappedAddress{port: c_port, address: c_ip}
    ])
    |> Message.with_integrity(key)
  end

  defp handle_allocate(listen_socket, five_tuple, key, msg) do
    with :ok <- is_not_retransmited?(msg, key, []),
         nil <- find_alloc(five_tuple),
         :ok <- check_requested_transport(msg),
         :ok <- check_dont_fragment(msg),
         {even_port, req_family, additional_family} <- get_addr_attributes(msg),
         :ok <- check_reservation_token(msg, even_port, req_family, additional_family),
         :ok <- check_family(msg, req_family, additional_family),
         :ok <- check_even_port(msg, additional_family),
         {:ok, alloc_port} <- get_available_port(msg),
         {:ok, lifetime} <- Utils.get_lifetime(msg) do
      Logger.info(
        "No allocation for five tuple #{inspect(five_tuple)}. Creating a new allocation"
      )

      {_src_ip, _src_port, client_ip, client_port, _proto} = five_tuple

      alloc_ip = Application.fetch_env!(:ex_turn, :public_ip)

      type = %Type{class: :success_response, method: msg.type.method}

      response =
        msg.transaction_id
        |> Message.new(type, [
          %XORRelayedAddress{port: alloc_port, address: alloc_ip},
          %Lifetime{lifetime: lifetime},
          %XORMappedAddress{port: client_port, address: client_ip}
        ])
        |> Message.with_integrity(key)

      {:ok, alloc_socket} =
        :gen_udp.open(
          alloc_port,
          [
            {:inet_backend, :socket},
            {:ifaddr, alloc_ip},
            {:active, true},
            {:recbuf, 1024 * 1024},
            :binary
          ]
        )

      {:ok, %Username{value: username}} = Message.get_attribute(msg, Username)

      child_spec = %{
        id: five_tuple,
        start:
          {ExTURN.AllocationHandler, :start_link,
           [listen_socket, alloc_socket, five_tuple, username, lifetime]}
      }

      {:ok, alloc_pid} = DynamicSupervisor.start_child(ExTURN.AllocationSupervisor, child_spec)
      :gen_udp.controlling_process(alloc_socket, alloc_pid)
      response
    else
      {:error, response} ->
        response

      _alloc ->
        Logger.warn("Allocation mismatch for #{inspect(five_tuple)}, message: #{inspect(msg)}")
        Utils.build_error(msg.transaction_id, msg.type.method, 437)
    end
  end

  defp check_requested_transport(msg) do
    case Message.get_attribute(msg, RequestedTransport) do
      {:ok, %RequestedTransport{protocol: :udp}} ->
        :ok

      {:ok, %RequestedTransport{protocol: :tcp}} ->
        Logger.warn("Unsupported REQUESTED-TRANSPORT: tcp. Rejecting.")
        {:error, Utils.build_error(msg.transaction_id, msg.type.method, 442)}

      _other ->
        Logger.warn("No or malformed REQUESTED-TRANSPORT. Rejecting.")
        {:error, Utils.build_error(msg.transaction_id, msg.type.method, 400)}
    end
  end

  defp check_dont_fragment(_msg) do
    # TODO: not supported at the moment
    :ok
  end

  defp check_reservation_token(msg, even_port, req_family, additional_family) do
    case Message.get_attribute(msg, ReservationToken) do
      {:ok, _reservation_token} ->
        if Enum.any?([even_port, req_family, additional_family], &(&1 != nil)) do
          {:error, Utils.build_error(msg.transaction_id, msg.type.method, 400)}
        else
          # TODO: implement reservation system
          {:error, Utils.build_error(msg.transaction_id, msg.type.method, 400)}
        end

      {:error, _reason} ->
        {:error, Utils.build_error(msg.transaction_id, msg.type.method, 400)}

      nil ->
        :ok
    end
  end

  defp check_family(msg, req_family, additional_family)
       when req_family != nil and additional_family != nil do
    {:error, Utils.build_error(msg.transaction_id, msg.type.method, 400)}
  end

  defp check_family(msg, req_family, additional_family) do
    do_check_family(msg, req_family, additional_family)
  end

  defp do_check_family(_msg, %RequestedAddressFamily{family: :ipv4}, _additional_family) do
    :ok
  end

  defp do_check_family(msg, %RequestedAddressFamily{family: :ipv6}, _additional_family) do
    # TODO: add support for IPv6
    {:error, Utils.build_error(msg.transaction_id, msg.type.method, 440)}
  end

  defp do_check_family(_msg, nil, _additional_family) do
    :ok
  end

  defp check_even_port(msg, additional_family) do
    case Message.get_attribute(msg, EvenPort) do
      {:ok, even_port} ->
        if even_port.r and additional_family do
          {:error, Utils.build_error(msg.transaction_id, msg.type.method, 400)}
        else
          # TODO: add support for EVEN-PORT 
          {:error, Utils.build_error(msg.transaction_id, msg.type.method, 508)}
        end

      {:error, _reason} ->
        {:error, Utils.build_error(msg.transaction_id, msg.type.method, 400)}

      nil ->
        :ok
    end
  end

  defp get_addr_attributes(msg) do
    even_port =
      case Message.get_attribute(msg, EvenPort) do
        {:ok, attr} -> attr
        _other -> nil
      end

    requested_address_family =
      case Message.get_attribute(msg, RequestedAddressFamily) do
        {:ok, attr} -> attr
        _other -> nil
      end

    additional_address_family =
      case Message.get_attribute(msg, AdditionalAddressFamily) do
        {:ok, attr} -> attr
        _other -> nil
      end

    {even_port, requested_address_family, additional_address_family}
  end

  defp find_alloc(five_tuple) do
    case Registry.lookup(Registry.Allocations, five_tuple) do
      [{allocation, _value}] -> allocation
      [] -> nil
    end
  end

  defp get_available_port(msg) do
    used_alloc_ports =
      Registry.Allocations
      |> Registry.select([{{:_, :_, :"$3"}, [], [:"$3"]}])
      |> MapSet.new()

    available_alloc_ports = MapSet.difference(@default_alloc_ports, used_alloc_ports)

    if MapSet.size(available_alloc_ports) == 0 do
      # TODO: what error code?
      {:error, Utils.build_error(msg.transaction_id, msg.type.method, 486)}
    else
      {:ok, Enum.random(available_alloc_ports)}
    end
  end

  defp is_not_retransmited?(_msg, _key, _allocation_requests) do
    # TODO: handle retransmitions, RFC 5766 6.2
    :ok
  end
end
