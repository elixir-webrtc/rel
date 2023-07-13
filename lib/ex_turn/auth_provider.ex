defmodule ExTURN.AuthProvider do
  @moduledoc false
  # REST service described in https://datatracker.ietf.org/doc/html/draft-uberti-rtcweb-turn-rest-00
  use Plug.Router

  alias ExTURN.Auth

  require Logger

  plug(CORSPlug)
  plug(:match)
  plug(:dispatch)

  post "/" do
    Logger.info("Received credential generation request")

    with conn <- fetch_query_params(conn),
         %{query_params: query_params} <- conn,
         %{"service" => "turn", "key" => key} <- query_params,
         true <- key == Application.fetch_env!(:ex_turn, :auth_provider_key) do
      username = Map.get(query_params, "username")
      {username, password, ttl} = Auth.generate_credentials(username)

      ip_addr = Application.fetch_env!(:ex_turn, :public_ip)
      port = Application.fetch_env!(:ex_turn, :listen_port)

      response =
        Jason.encode!(%{
          "username" => username,
          "password" => password,
          "ttl" => ttl,
          "uris" => ["turn:#{ip_to_string(ip_addr)}:#{port}?transport=udp"]
        })

      Logger.info("Generated credentials: #{inspect(username)}, #{inspect(password)}")

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(200, response)
    else
      false -> send_resp(conn, 401, "unauthenticated")
      _other -> send_resp(conn, 400, "invalid request")
    end
  end

  match _ do
    send_resp(conn, 400, "invalid request")
  end

  defp ip_to_string(addr) when is_tuple(addr) do
    addr_list = Tuple.to_list(addr)

    {base, delimiter} =
      case length(addr_list) do
        4 -> {10, "."}
        8 -> {16, ":"}
      end

    addr_str =
      addr_list
      |> Enum.map_join(delimiter, &Integer.to_string(&1, base))

    if base == 10, do: addr_str, else: "[#{addr_str}]"
  end
end
