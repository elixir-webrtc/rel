defmodule Rel.Listener do
  @moduledoc false
  use Task, restart: :permanent

  require Logger

  alias Rel.Attribute.{
    EvenPort,
    Lifetime,
    RequestedAddressFamily,
    RequestedTransport,
    ReservationToken,
    XORRelayedAddress
  }

  alias Rel.AllocationHandler
  alias Rel.Auth
  alias Rel.Utils

  alias ExSTUN.Message
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{Username, XORMappedAddress}

  @default_alloc_ports MapSet.new(49_152..65_535)

  @spec start_link(term()) :: {:ok, pid()}
  def start_link(args) do
    Task.start_link(__MODULE__, :listen, args)
  end

  @spec listen(:inet.ip_address(), :inet.port_number()) :: :ok
  def listen(ip, port) do
    listener_addr = "#{:inet.ntoa(ip)}:#{port}/UDP"

    Logger.info("Starting a new listener on: #{listener_addr}")
    Logger.metadata(listener: listener_addr)

    # {:ok, socket} =
    #   :gen_udp.open(
    #     port,
    #     [
    #       {:inet_backend, :socket},
    #       {:ifaddr, ip},
    #       {:active, false},
    #       {:recbuf, 1024 * 1024},
    #       # {:reuseport, true},
    #       :binary
    #     ]
    #   )
    #
    # :inet.setopts(socket, [reuseaddr: true, reuseport: true])

    {:ok, socket} =
      :socket.open(:inet, :dgram, :udp)

    :ok = :socket.setopt(socket, {:socket, :reuseport}, true)
    :ok = :socket.bind(socket, %{family: :inet, addr: ip, port: port})

    # spawn(Rel.Monitor, :start, [self(), socket])

    recv_loop(socket)
  end

  defp recv_loop(socket) do
    # case :gen_udp.recv(socket, 0) do
    case :socket.recvfrom(socket) do
      {:ok, {%{addr: client_addr, port: client_port}, packet}} ->
        IO.inspect(self(), label: :RECEIVED)
        # {:ok, {client_addr, client_port, packet}} ->
        :telemetry.execute([:listener, :client], %{inbound: byte_size(packet)})

        process(socket, client_addr, client_port, packet)
        recv_loop(socket)

      {:error, reason} ->
        Logger.error("Couldn't receive from the socket, reason: #{inspect(reason)}")
    end
  end

  defp process(socket, client_ip, client_port, <<two_bits::2, _rest::bitstring>> = packet) do
    # {:ok, {server_ip, server_port}} = :inet.sockname(socket)
    {server_ip, server_port} = {{0, 0, 0, 0}, 3478}
    five_tuple = {client_ip, client_port, server_ip, server_port, :udp}

    Logger.metadata(client: "#{:inet.ntoa(client_ip)}:#{client_port}")

    # TODO: according to RFCs, unknown comprehension-required
    # attributes should result in error response 420, but oh well
    case two_bits do
      0 ->
        case Message.decode(packet) do
          {:ok, msg} ->
            handle_stun_message(socket, five_tuple, msg)

          {:error, reason} ->
            Logger.warning(
              "Failed to decode STUN packet, reason: #{inspect(reason)}, packet: #{inspect(packet)}"
            )
        end

      1 ->
        handle_channel_message(five_tuple, packet)

      _other ->
        Logger.warning(
          "Received packet that is neither STUN formatted nor ChannelData, packet: #{inspect(packet)}"
        )
    end

    Logger.metadata(client: nil)
  end

  defp handle_stun_message(
         socket,
         five_tuple,
         %Message{type: %Type{class: :request, method: :binding}} = msg
       ) do
    Logger.info("Received 'binding' request")
    {c_ip, c_port, _, _, _} = five_tuple

    type = %Type{class: :success_response, method: :binding}

    response =
      msg.transaction_id
      |> Message.new(type, [
        %XORMappedAddress{port: c_port, address: c_ip}
      ])
      |> Message.encode()

    # :ok = :gen_udp.send(socket, c_ip, c_port, response)
    :ok = :socket.sendto(socket, response, %{family: :inet, addr: c_ip, port: c_port})
  end

  defp handle_stun_message(
         socket,
         five_tuple,
         %Message{type: %Type{class: :request, method: :allocate}} = msg
       ) do
    Logger.info("Received new allocation request")
    {c_ip, c_port, _, _, _} = five_tuple

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
      relay_ip = Application.fetch_env!(:rel, :relay_ip)
      external_relay_ip = Application.fetch_env!(:rel, :external_relay_ip)

      type = %Type{class: :success_response, method: msg.type.method}

      response =
        msg.transaction_id
        |> Message.new(type, [
          %XORRelayedAddress{port: alloc_port, address: external_relay_ip},
          %Lifetime{lifetime: lifetime},
          %XORMappedAddress{port: c_port, address: c_ip}
        ])
        |> Message.with_integrity(key)
        |> Message.encode()

      {:ok, alloc_socket} =
        :gen_udp.open(
          alloc_port,
          [
            {:inet_backend, :socket},
            {:ifaddr, relay_ip},
            {:active, true},
            {:recbuf, 1024 * 1024},
            :binary
          ]
        )

      Logger.info("Succesfully created allocation, relay port: #{alloc_port}")

      {:ok, %Username{value: username}} = Message.get_attribute(msg, Username)

      {:ok, alloc_pid} =
        DynamicSupervisor.start_child(
          Rel.AllocationSupervisor,
          {Rel.AllocationHandler, [five_tuple, alloc_socket, socket, username, lifetime]}
        )

      :ok = :gen_udp.controlling_process(alloc_socket, alloc_pid)

      # :ok = :gen_udp.send(socket, c_ip, c_port, response)
      :ok = :socket.sendto(socket, response, %{family: :inet, addr: c_ip, port: c_port})
    else
      {:error, reason} ->
        {response, log_msg} = Utils.build_error(reason, msg.transaction_id, msg.type.method)
        Logger.warning(log_msg)
        # :ok = :gen_udp.send(socket, c_ip, c_port, response)
        :ok = :socket.sendto(socket, response, %{family: :inet, addr: c_ip, port: c_port})
    end
  end

  defp handle_stun_message(socket, five_tuple, msg) do
    case fetch_allocation(five_tuple) do
      {:ok, alloc} ->
        AllocationHandler.process_stun_message(alloc, msg)

      {:error, :allocation_not_found = reason} ->
        {c_ip, c_port, _, _, _} = five_tuple
        {response, _log_msg} = Utils.build_error(reason, msg.transaction_id, msg.type.method)

        Logger.warning(
          "No allocation and this is not an 'allocate'/'binding' request, message: #{inspect(msg)}"
        )

        # TODO: should this be explicit or maybe silent?
        # :ok = :gen_udp.send(socket, c_ip, c_port, response)
        :ok = :socket.sendto(socket, response, %{family: :inet, addr: c_ip, port: c_port})
    end
  end

  defp handle_channel_message(five_tuple, <<msg::binary>>) do
    # TODO: are Registry entries removed fast enough?
    case fetch_allocation(five_tuple) do
      {:ok, alloc} ->
        AllocationHandler.process_channel_message(alloc, msg)

      {:error, :allocation_not_found} ->
        # TODO: should this be silent?
        Logger.warning("No allocation and is not a STUN message, silently discarded")
    end
  end

  defp is_not_retransmited?(_msg, _key, _allocation_requests) do
    # TODO: handle retransmitions, RFC 5766 6.2
    :ok
  end

  defp fetch_allocation(five_tuple) do
    case Registry.lookup(Registry.Allocations, five_tuple) do
      [{allocation, _value}] -> {:ok, allocation}
      [] -> {:error, :allocation_not_found}
    end
  end

  defp refute_allocation(five_tuple) do
    case fetch_allocation(five_tuple) do
      {:error, :allocation_not_found} -> :ok
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
