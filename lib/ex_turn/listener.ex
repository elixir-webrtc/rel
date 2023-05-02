defmodule ExTURN.Listener do
  require Logger

  alias ExTURN.STUN.Attribute.{
    AdditionalAddressFamily,
    EvenPort,
    Lifetime,
    RequestedTransport,
    ReservationToken,
    RequestedAddressFamily,
    XORRelayedAddress
  }

  alias ExTURN.Utils

  alias ExStun.Message
  alias ExStun.Message.Type
  alias ExStun.Message.Attribute.{ErrorCode, XORMappedAddress}

  def listen(ip, port) do
    Logger.info("Starting a new listener ip: #{inspect(ip)}, port: #{port}, proto: udp")

    {:ok, socket} =
      :gen_udp.open(
        port,
        inet_backend: :socket,
        ifaddr: ip,
        active: false,
        recbuf: 1024 * 1024
      )

    spawn(ExTURN.Monitor, :start, [self(), socket])

    recv_loop(socket)
  end

  defp recv_loop(socket) do
    case :gen_udp.recv(socket, 0) do
      {:ok, {client_addr, client_port, packet}} ->
        packet = :binary.list_to_bin(packet)
        process(socket, client_addr, client_port, packet)
        recv_loop(socket)

      {:error, reason} ->
        Logger.error(
          "Couldn't receive from UDP socket #{inspect(socket)}, reason: #{inspect(reason)}"
        )
    end
  end

  defp process(socket, client_ip, client_port, packet) do
    {:ok, {server_ip, server_port}} = :inet.sockname(socket)
    five_tuple = {client_ip, client_port, server_ip, server_port, :udp}

    <<first_byte::8, _rest::binary>> = packet

    cond do
      first_byte in 0..3 ->
        with {:ok, msg} <- ExStun.Message.decode(packet),
             :ok <- handle_message(socket, five_tuple, msg) do
          :ok
        else
          {:error, reason} ->
            Logger.warn("""
            Couldn't decode STUN message, reason: #{inspect(reason)}, message: #{inspect(packet)}
            """)

          response ->
            :gen_udp.send(socket, {client_ip, client_port}, response)
        end

      first_byte in 64..79 ->
        :ok = handle_message(socket, five_tuple, packet)

      true ->
        Logger.warn("Unexpected message type, first byte: #{first_byte}")
    end
  end

  defp handle_message(socket, five_tuple, msg) do
    case msg do
      %Message{type: %Type{class: :request, method: :allocate}} ->
        handle_allocate_request(socket, five_tuple, msg)

      _other ->
        case find_alloc(five_tuple) do
          nil ->
            Logger.info("""
            No allocation for five tuple #{inspect(five_tuple)} and this is not an allocate request. \
            Ignoring message: #{inspect(msg)}\
            """)

          alloc ->
            send(alloc, {:msg, msg})
        end

        :ok
    end
  end

  defp handle_allocate_request(listen_socket, five_tuple, msg) do
    with {:ok, key} <- Utils.authenticate(msg),
         nil <- find_alloc(five_tuple),
         :ok <- check_requested_transport(msg),
         :ok <- check_dont_fragment(msg),
         {even_port, req_family, additional_family} <- get_addr_attributes(msg),
         :ok <- check_reservation_token(msg, even_port, req_family, additional_family),
         :ok <- check_family(msg, req_family, additional_family),
         :ok <- check_even_port(msg, additional_family) do
      Logger.info(
        "No allocation for five tuple #{inspect(five_tuple)}. Creating a new allocation"
      )

      {_src_ip, _src_port, client_ip, client_port, _proto} = five_tuple

      # TODO dont hardcode alloc address
      alloc_port = Enum.random(49152..65535)
      alloc_ip = {127, 0, 0, 1}

      type = %Type{class: :success_response, method: msg.type.method}

      response =
        Message.new(msg.transaction_id, type, [
          %XORRelayedAddress{family: :ipv4, port: alloc_port, address: alloc_ip},
          # one hour
          %Lifetime{lifetime: 3600},
          %XORMappedAddress{family: :ipv4, port: client_port, address: client_ip}
        ])
        |> Message.encode_with_int(key)

      {:ok, alloc_socket} =
        :gen_udp.open(
          alloc_port,
          inet_backend: :socket,
          ifaddr: alloc_ip,
          active: true,
          recbuf: 1024 * 1024
        )

      child_spec = %{
        id: five_tuple,
        start: {ExTURN.AllocationHandler, :start_link, [listen_socket, alloc_socket, five_tuple]}
      }

      {:ok, alloc_pid} = DynamicSupervisor.start_child(ExTURN.AllocationSupervisor, child_spec)
      :gen_udp.controlling_process(alloc_socket, alloc_pid)
      response
    else
      {:error, response} ->
        Message.encode(response)

      alloc ->
        Logger.warn(
          "Allocation mismatch #{inspect(alloc)} #{inspect(five_tuple)} #{inspect(msg)}"
        )

        type = %Type{class: :error_response, method: :allocate}
        Message.new(msg.transaction_id, type, [%ErrorCode{code: 437}]) |> Message.encode()
    end
  end

  defp check_requested_transport(msg) do
    # The server checks if the request contains
    # a REQUESTED-TRANSPORT attribute. If the
    # REQUESTED-TRANSPORT attribute is not included
    # or is malformed, the server rejects the request
    # with a 400 (Bad Request) error. Otherwise,
    # if the attribute is included but specifies
    # a protocol that is not supported by the server,
    # the server rejects the request with a 442
    # (Unsupported Transport Protocol) error.
    case RequestedTransport.get_from_message(msg) do
      {:ok, %RequestedTransport{protocol: :udp}} ->
        :ok

      {:ok, %RequestedTransport{protocol: :tcp}} ->
        Logger.warn("Unsupported REQUESTED-TRANSPORT: tcp. Rejecting.")
        type = %Type{class: :error_response, method: msg.type.method}
        response = Message.new(msg.transaction_id, type, [%ErrorCode{code: 442}])
        {:error, response}

      _other ->
        Logger.warn("No or malformed REQUESTED-TRANSPORT. Rejecting.")
        type = %Type{class: :error_response, method: msg.type.method}
        response = Message.new(msg.transaction_id, type, [%ErrorCode{code: 400}])
        {:error, response}
    end
  end

  defp check_dont_fragment(_msg) do
    # The request may contain a DONT-FRAGMENT attribute.
    # If it does, but the server does not support sending
    # UDP datagrams with the DF bit set to 1 (see Sections 14
    # and 15), then the server treats the DONT-FRAGMENT
    # attribute in the Allocate request as an unknown
    # comprehension-required attribute.¶

    # TODO handle this
    :ok
  end

  defp check_reservation_token(msg, even_port, req_family, additional_family) do
    # The server checks if the request contains a RESERVATION-TOKEN
    # attribute. If yes, and the request also contains an EVEN-PORT
    # or REQUESTED-ADDRESS-FAMILY or ADDITIONAL-ADDRESS-FAMILY
    # attribute, the server rejects the request with a 400 (Bad Request)
    # error. Otherwise, it checks to see if the token is valid
    # (i.e., the token is in range and has not expired, and the
    # corresponding relayed transport address is still available).
    # If the token is not valid for some reason, the server rejects
    # the request with a 508 (Insufficient Capacity) error.
    case ReservationToken.get_from_message(msg) do
      {:ok, _reservation_token} ->
        if Enum.any?([even_port, req_family, additional_family], &(&1 != nil)) do
          type = %Type{class: :error_response, method: msg.type.method}
          response = Message.new(msg.transaction_id, type, [%ErrorCode{code: 400}])
          {:error, response}
        else
          # TODO check token
          # for now we don't support reservation token
          type = %Type{class: :error_response, method: msg.type.method}
          response = Message.new(msg.transaction_id, type, [%ErrorCode{code: 400}])
          {:error, response}
        end

      {:error, _reason} ->
        type = %Type{class: :error_response, method: msg.type.method}
        response = Message.new(msg.transaction_id, type, [%ErrorCode{code: 500}])
        {:error, response}

      nil ->
        :ok
    end
  end

  defp check_family(msg, req_family, additional_family)
       when req_family != nil and additional_family != nil do
    # 6. The server checks if the request contains both REQUESTED-ADDRESS-FAMILY
    # and ADDITIONAL-ADDRESS-FAMILY attributes. If yes, then the server rejects
    # the request with a 400 (Bad Request) error
    type = %Type{class: :error_response, method: msg.type.method}
    response = Message.new(msg.transaction_id, type, [%ErrorCode{code: 400}])
    {:error, response}
  end

  defp check_family(msg, req_family, additional_family) do
    # 7. If the server does not support the address family requested by the client
    # in REQUESTED-ADDRESS-FAMILY, or if the allocation of the requested address
    # family is disabled by local policy, it MUST generate an Allocate error response,
    # and it MUST include an ERROR-CODE attribute with the 440 (Address Family not
    # Supported) response code. If the REQUESTED-ADDRESS-FAMILY attribute is absent
    # and the server does not support the IPv4 address family, the server MUST include
    # an ERROR-CODE attribute with the 440 (Address Family not Supported) response code.
    # If the REQUESTED-ADDRESS-FAMILY attribute is absent and the server supports
    # the IPv4 address family, the server MUST allocate an IPv4 relayed transport
    # address for the TURN client.
    do_check_family(msg, req_family, additional_family)
  end

  defp do_check_family(_msg, %RequestedAddressFamily{family: :ipv4}, _additional_family) do
    :ok
  end

  defp do_check_family(msg, %RequestedAddressFamily{family: :ipv6}, _additional_family) do
    # TODO add support for ipv6
    type = %Type{class: :error_response, method: msg.type.method}
    response = Message.new(msg.transaction_id, type, [%ErrorCode{code: 440}])
    {:error, response}
  end

  defp do_check_family(_msg, nil, _additional_family) do
    :ok
  end

  defp check_even_port(msg, additional_family) do
    # 8. The server checks if the request contains an EVEN-PORT attribute
    # with the R bit set to 1. If yes, and the request also contains an
    # ADDITIONAL-ADDRESS-FAMILY attribute, the server rejects the request
    # with a 400 (Bad Request) error. Otherwise, the server checks if it
    # can satisfy the request (i.e., can allocate a relayed transport
    # address as described below). If the server cannot satisfy the request,
    # then the server rejects the request with a 508 (Insufficient Capacity) error.
    case EvenPort.get_from_message(msg) do
      {:ok, even_port} ->
        if even_port.r and additional_family do
          type = %Type{class: :error_response, method: msg.type.method}
          response = Message.new(msg.transaction_id, type, [%ErrorCode{code: 400}])
          {:error, response}
        else
          # TODO add support for EVEN-PORT
          type = %Type{class: :error_response, method: msg.type.method}
          response = Message.new(msg.transaction_id, type, [%ErrorCode{code: 508}])
          {:error, response}
        end

      {:error, _reason} ->
        type = %Type{class: :error_response, method: msg.type.method}
        response = Message.new(msg.transaction_id, type, [%ErrorCode{code: 400}])
        {:error, response}

      nil ->
        :ok
    end
  end

  defp get_addr_attributes(msg) do
    even_port =
      case EvenPort.get_from_message(msg) do
        {:ok, attr} -> attr
        _other -> nil
      end

    requested_address_family =
      case RequestedAddressFamily.get_from_message(msg) do
        {:ok, attr} -> attr
        _other -> nil
      end

    additional_address_family =
      case AdditionalAddressFamily.get_from_message(msg) do
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
end
