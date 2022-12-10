defmodule ExTURN.Listener do
  require Logger

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
        case Utils.authenticate(msg) do
          :ok ->
            case Registry.lookup(Registry.Allocations, five_tuple) do
              [{_allocation, _value}] ->
                Logger.warn("Allocation mismatch #{inspect(five_tuple)}")
                type = %Type{class: :error_response, method: :allocate}
                Message.new(msg.transaction_id, type, [%ErrorCode{code: 437}])

              [] ->
                Logger.info(
                  "No allocation for five tuple #{inspect(five_tuple)}. Creating allocation"
                )

                child_spec = %{
                  id: five_tuple,
                  start: {ExTURN.AllocationHandler, :start_link, [socket, five_tuple]}
                }

                DynamicSupervisor.start_child(ExTURN.AllocationSupervisor, child_spec)
                :ok
            end

          {:error, response} ->
            response
        end

      _other ->
        case Registry.lookup(Registry.Allocations, five_tuple) do
          [{allocation, _value}] ->
            send(allocation, {:msg, msg})

          [] ->
            Logger.info("""
            No allocation for five tuple #{inspect(five_tuple)} and this is not an allocate request. \
            Ignoring message: #{inspect(msg)}"
            """)
        end

        :ok
    end
  end
end
