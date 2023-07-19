defmodule ExTURN.Listener do
  @moduledoc false
  require Logger

  alias ExTURN.Attribute.{
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

  def listen(ip, port) do
    listener_addr = "#{:inet.ntoa(ip)}:#{port}/UDP"

    Logger.info("Starting a new listener on #{listener_addr}")
    Logger.metadata(listener: listener_addr)

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
      listener_id: listener_addr,
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
        Logger.error("Couldn't receive from the socket, reason: #{inspect(reason)}")
    end
  end

  defp process(socket, client_ip, client_port, <<first_byte::8, _rest::binary>> = packet) do
    {:ok, {server_ip, server_port}} = :inet.sockname(socket)
    five_tuple = {client_ip, client_port, server_ip, server_port, :udp}

    Logger.metadata(client: "#{:inet.ntoa(client_ip)}:#{client_port}")

    if first_byte in 0..3 do
      # FIXME: according to RFCs, unknown comprehension-required
      # attributes should result in error response 420, but oh well
      case Message.decode(packet) do
        {:ok, msg} ->
          handle_message(socket, five_tuple, msg)

        {:error, reason} ->
          Logger.warning(
            "Failed to decode STUN packet, reason: #{inspect(reason)}, packet: #{inspect(packet)}"
          )
      end
    else
      handle_message(socket, five_tuple, packet)
    end

    Logger.metadata(client: nil)
  end

  defp handle_message(
         socket,
         five_tuple,
         %Message{type: %Type{class: :request, method: :binding}} = msg
       ) do
    Logger.info("Received binding request")
    {c_ip, c_port, _, _, _} = five_tuple

    response =
      case Auth.authenticate(msg) do
        {:ok, key} ->
          type = %Type{class: :success_response, method: :binding}

          msg.transaction_id
          |> Message.new(type, [
            %XORMappedAddress{port: c_port, address: c_ip}
          ])
          |> Message.with_integrity(key)

        {:error, response} ->
          response
      end

    :gen_udp.send(socket, c_ip, c_port, Message.encode(response))
  end

  defp handle_message(
         socket,
         five_tuple,
         %Message{type: %Type{class: :request, method: :allocate}} = msg
       ) do
    Logger.info("Received new allocation request")
    {c_ip, c_port, _, _, _} = five_tuple

    result =
      with {:ok, key} <- Auth.authenticate(msg),
           :ok <- is_not_retransmited?(msg, key, []),
           :ok <- refute_allocation(five_tuple),
           :ok <- check_requested_transport(msg),
           :ok <- check_dont_fragment(msg),
           {:ok, even_port} <- get_even_port(msg),
           {:ok, req_family} <- get_requested_address_family(msg),
           :ok <- check_reservation_token(msg, even_port, req_family),
           :ok <- check_family(req_family),
           :ok <- check_even_port(even_port),
           {:ok, alloc_port} <- get_available_port(),
           {:ok, lifetime} <- Utils.get_lifetime(msg) do
        alloc_ip = Application.fetch_env!(:ex_turn, :public_ip)

        type = %Type{class: :success_response, method: msg.type.method}

        response =
          msg.transaction_id
          |> Message.new(type, [
            %XORRelayedAddress{port: alloc_port, address: alloc_ip},
            %Lifetime{lifetime: lifetime},
            %XORMappedAddress{port: c_port, address: c_ip}
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

        Logger.info("Succesfully created allocation")

        {:ok, %Username{value: username}} = Message.get_attribute(msg, Username)

        child_spec = %{
          id: five_tuple,
          restart: :transient,
          start:
            {ExTURN.AllocationHandler, :start_link,
             [socket, alloc_socket, five_tuple, username, lifetime]}
        }

        {:ok, alloc_pid} = DynamicSupervisor.start_child(ExTURN.AllocationSupervisor, child_spec)
        :gen_udp.controlling_process(alloc_socket, alloc_pid)
        {:ok, response}
      else
        {:error, %Message{} = response} ->
          {:ok, response}

        {:error, :allocation_exists} ->
          {"Allocation mismatch: allocation already exists, rejected", 437}

        {:error, :requested_transport_tcp} ->
          {"Unsupported REQUESTED-TRANSPORT: TCP, rejected", 442}

        {:error, :invalid_requested_transport} ->
          {"No or malformed REQUESTED-TRANSPORT, rejected", 400}

        {:error, :invalid_even_port} ->
          {"Failed to decode EVEN-PORT, rejected", 400}

        {:error, :invalid_requested_address_family} ->
          {"Failed to decode REQUESTED-ADDRESS-FAMILY, rejected", 400}

        {:error, :reservation_token_with_others} ->
          {"RESERVATION-TOKEN and (EVEN-PORT|REQUESTED-FAMILY) in the message, rejected", 400}

        {:error, :reservation_token_unsupported} ->
          {"RESERVATION-TOKEN unsupported, rejected", 400}

        {:error, :invalid_reservation_token} ->
          {"Failed to decode RESERVATION-TOKEN, rejected", 400}

        {:error, :requested_address_family_unsupported} ->
          {"REQUESTED-ADDRESS-FAMILY with IPv6 unsupported, rejected", 440}

        {:error, :even_port_unsupported} ->
          {"EVEN-PORT unsupported, rejected", 400}

        {:error, :out_of_ports} ->
          {"No available ports left, rejected", 508}

        {:error, :invalid_lifetime} ->
          {"Failed to decode LIFETIME, rejected", 400}
      end

    response =
      case result do
        {:ok, response} ->
          response

        {warning, error_code} ->
          Logger.warning(warning)
          Utils.build_error(msg.transaction_id, msg.type.method, error_code)
      end

    :gen_udp.send(socket, c_ip, c_port, Message.encode(response))
  end

  defp handle_message(socket, five_tuple, msg) do
    case fetch_allocation(five_tuple) do
      {:ok, alloc} ->
        AllocationHandler.process_message(alloc, msg)

      {:error, :not_found} ->
        {c_ip, c_port, _, _, _} = five_tuple

        case msg do
          %Message{} ->
            Logger.warn(
              "No allocation and this is not an allocate/binding request, message: #{inspect(msg)}"
            )

            msg.transaction_id
            |> Utils.build_error(msg.type.method, 437)
            |> Message.encode()
            |> then(&:gen_udp.send(socket, c_ip, c_port, &1))

          _other ->
            Logger.warn("No allocation and is not a STUN message, silently discarded")
            :ok
        end
    end
  end

  defp is_not_retransmited?(_msg, _key, _allocation_requests) do
    # TODO: handle retransmitions, RFC 5766 6.2
    :ok
  end

  defp fetch_allocation(five_tuple) do
    case Registry.lookup(Registry.Allocations, five_tuple) do
      [{allocation, _value}] -> {:ok, allocation}
      [] -> {:error, :not_found}
    end
  end

  defp refute_allocation(five_tuple) do
    case fetch_allocation(five_tuple) do
      {:error, :not_found} -> :ok
      {:ok, _alloc} -> {:error, :allocation_exists}
    end
  end

  defp check_requested_transport(msg) do
    case Message.get_attribute(msg, RequestedTransport) do
      {:ok, %RequestedTransport{protocol: :udp}} -> :ok
      {:ok, %RequestedTransport{protocol: :tcp}} -> {:error, :requested_transport_tcp}
      _other -> {:error, :invalid_requested_transport}
    end
  end

  defp check_dont_fragment(_msg) do
    # TODO: not supported at the moment, proabably should return 420 error
    :ok
  end

  defp get_even_port(msg) do
    case Message.get_attribute(msg, EvenPort) do
      {:error, _reason} -> {:error, :invalid_even_port}
      {:ok, even_port} -> {:ok, even_port}
      nil -> {:ok, nil}
    end
  end

  defp get_requested_address_family(msg) do
    case Message.get_attribute(msg, RequestedAddressFamily) do
      {:error, _reason} -> {:error, :invalid_requested_address_family}
      {:ok, requested_address_family} -> {:ok, requested_address_family}
      nil -> {:ok, nil}
    end
  end

  defp check_reservation_token(msg, even_port, req_family) do
    case Message.get_attribute(msg, ReservationToken) do
      {:ok, _reservation_token} ->
        if Enum.any?([even_port, req_family], &(&1 != nil)) do
          {:error, :reservation_token_with_others}
        else
          # TODO: implement reservation_token
          {:error, :reservation_token_unsupported}
        end

      {:error, _reason} ->
        {:error, :invalid_reservation_token}

      nil ->
        :ok
    end
  end

  defp check_family(req_family)
       when req_family in [nil, %RequestedAddressFamily{family: :ipv4}],
       do: :ok

  defp check_family(%RequestedAddressFamily{family: :ipv6}) do
    # TODO: implement requested address family
    {:error, :requested_address_family_unsupported}
  end

  defp check_even_port(nil), do: :ok

  defp check_even_port(%EvenPort{}) do
    # TODO: implement even port
    {:error, :even_port_unsupported}
  end

  defp get_available_port() do
    used_alloc_ports =
      Registry.Allocations
      |> Registry.select([{{:_, :_, :"$3"}, [], [:"$3"]}])
      |> MapSet.new()

    available_alloc_ports = MapSet.difference(@default_alloc_ports, used_alloc_ports)

    if MapSet.size(available_alloc_ports) == 0 do
      {:error, :out_of_ports}
    else
      {:ok, Enum.random(available_alloc_ports)}
    end
  end
end
