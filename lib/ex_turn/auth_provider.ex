defmodule ExTURN.AuthProvider do
  @moduledoc false
  # REST service described in https://datatracker.ietf.org/doc/html/draft-uberti-rtcweb-turn-rest-00
  use Plug.Router

  require Logger

  alias ExTURN.Auth

  plug(CORSPlug)
  plug(:match)
  plug(:dispatch)

  post "/" do
    Logger.info("Received credential generation request from #{:inet.ntoa(conn.remote_ip)}")

    with conn <- fetch_query_params(conn),
         %{query_params: query_params} <- conn,
         %{"service" => "turn"} <- query_params do
      username = Map.get(query_params, "username")
      {username, password, ttl} = Auth.generate_credentials(username)

      ip_addr = Application.fetch_env!(:ex_turn, :external_ip)
      port = Application.fetch_env!(:ex_turn, :listen_port)

      response =
        Jason.encode!(%{
          "username" => username,
          "password" => password,
          "ttl" => ttl,
          "uris" => ["turn:#{:inet.ntoa(ip_addr)}:#{port}?transport=udp"]
        })

      Logger.info("Generated credentials for #{:inet.ntoa(conn.remote_ip)}")

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(200, response)
    else
      _other ->
        conn = fetch_query_params(conn)

        Logger.info(
          "Invalid credential request from #{:inet.ntoa(conn.remote_ip)}, query params: #{inspect(conn.query_params)}"
        )

        send_resp(conn, 400, "invalid request")
    end
  end

  match _ do
    send_resp(conn, 400, "invalid request")
  end
end
