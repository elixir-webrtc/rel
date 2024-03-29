defmodule Rel.AuthProvider do
  @moduledoc false
  # REST service described in https://datatracker.ietf.org/doc/html/draft-uberti-rtcweb-turn-rest-00
  defmodule ConditionalCORSPlug do
    @moduledoc false
    import Plug.Conn

    def init(_opts), do: []

    def call(conn, _opts) do
      allow? = Application.fetch_env!(:rel, :auth_allow_cors?)

      if allow? do
        CORSPlug.call(conn, CORSPlug.init([]))
      else
        conn
      end
    end
  end

  use Plug.Router

  require Logger

  alias Rel.Auth

  plug(ConditionalCORSPlug)
  plug(:match)
  plug(:dispatch)

  post "/" do
    Logger.info("Received credential generation request from #{:inet.ntoa(conn.remote_ip)}")

    with conn <- fetch_query_params(conn),
         %{query_params: query_params} <- conn,
         %{"service" => "turn"} <- query_params do
      username = Map.get(query_params, "username")
      {username, password, ttl} = Auth.generate_credentials(username)

      ip_addr = Application.fetch_env!(:rel, :external_listen_ip)
      port = Application.fetch_env!(:rel, :listen_port)

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
