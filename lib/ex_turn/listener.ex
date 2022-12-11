defmodule ExTURN.Listener do
  require Logger

  alias ExTURN.STUN.Attribute.RequestedTransport
  alias ExStun.Message
  alias ExStun.Message.Type
  alias ExStun.Message.Attribute.ErrorCode

  alias ExTURN.Utils

  def listen(ip, port, :udp = proto) do
    Logger.info("Starting new listener ip: #{inspect(ip)}, port: #{port}, proto: #{proto}")

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

    with {:ok, msg} <- ExStun.Message.decode(packet) do
      case handle_message(socket, five_tuple, msg) do
        :ok -> :ok
        response -> :gen_udp.send(socket, {client_ip, client_port}, Message.encode(response))
      end
    else
      {:error, reason} ->
        Logger.warn("""
        Couldn't decode STUN message, reason: #{inspect(reason)}, message: #{inspect(packet)}
        """)
    end
  end

  defp handle_message(socket, five_tuple, %Message{type: type} = msg) do
    case type do
      %Type{class: :request, method: :allocate} ->
        handle_allocate_request(socket, five_tuple, msg)

      _other ->
        case find_alloc(five_tuple) do
          nil ->
            Logger.info("""
            No allocation for five tuple #{inspect(five_tuple)} and this is not an allocate request. \
            Ignoring message: #{inspect(msg)}"
            """)

          alloc ->
            send(alloc, {:msg, msg})
        end

        :ok
    end
  end

  defp handle_allocate_request(socket, five_tuple, msg) do
    with :ok <- Utils.authenticate(msg),
         nil <- find_alloc(five_tuple),
         :ok <- check_requested_transport(msg),
         :ok <- check_dont_fragment(msg) do
      Logger.info("No allocation for five tuple #{inspect(five_tuple)}. Creating allocation")

      child_spec = %{
        id: five_tuple,
        start: {ExTURN.AllocationHandler, :start_link, [socket, five_tuple]}
      }

      DynamicSupervisor.start_child(ExTURN.AllocationSupervisor, child_spec)
      :ok
    else
      {:error, response} ->
        response

      _alloc ->
        Logger.warn("Allocation mismatch #{inspect(five_tuple)}")
        type = %Type{class: :error_response, method: :allocate}
        Message.new(msg.transaction_id, type, [%ErrorCode{code: 437}])
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
        IO.inspect(msg)
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

  defp find_alloc(five_tuple) do
    case Registry.lookup(Registry.Allocations, five_tuple) do
      [{allocation, _value}] -> allocation
      [] -> nil
    end
  end
end
