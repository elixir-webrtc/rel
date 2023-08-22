defmodule Rel.App do
  @moduledoc false
  use Application

  require Logger

  @version Mix.Project.config()[:version]

  @impl true
  def start(_, _) do
    Logger.info("Starting Rel v#{@version}")

    auth_ip = Application.fetch_env!(:rel, :auth_ip)
    auth_port = Application.fetch_env!(:rel, :auth_port)
    auth_use_tls? = Application.fetch_env!(:rel, :auth_use_tls?)
    auth_keyfile = Application.fetch_env!(:rel, :auth_keyfile)
    auth_certfile = Application.fetch_env!(:rel, :auth_certfile)

    auth_opts =
      if auth_use_tls? do
        [
          scheme: :https,
          certfile: auth_certfile,
          keyfile: auth_keyfile
        ]
      else
        [scheme: :http]
      end

    auth_opts =
      auth_opts ++
        [plug: Rel.AuthProvider, ip: auth_ip, port: auth_port]

    metrics_ip = Application.fetch_env!(:rel, :metrics_ip)
    metrics_port = Application.fetch_env!(:rel, :metrics_port)
    metrics_opts = [metrics: metrics(), port: metrics_port, plug_cowboy_opts: [ip: metrics_ip]]

    children = [
      Rel.ListenerSupervisor,
      {DynamicSupervisor, strategy: :one_for_one, name: Rel.AllocationSupervisor},
      {Registry, keys: :unique, name: Registry.Allocations},
      {TelemetryMetricsPrometheus, metrics_opts},
      {Bandit, auth_opts}
    ]

    metrics_endpoint = "http://#{:inet.ntoa(metrics_ip)}:#{metrics_port}/metrics"
    Logger.info("Starting Prometheus metrics endpoint at: #{metrics_endpoint}")

    scheme = if(auth_use_tls?, do: "https", else: "http")
    auth_endpoint = "#{scheme}://#{:inet.ntoa(auth_ip)}:#{auth_port}/"
    Logger.info("Starting credentials endpoint at: #{auth_endpoint}")

    Supervisor.start_link(children, strategy: :one_for_one)
  end

  defp metrics() do
    import Telemetry.Metrics

    [
      sum(
        "turn.allocations.created.total",
        event_name: [:allocations],
        measurement: :created
      ),
      sum(
        "turn.allocations.expired.total",
        event_name: [:allocations],
        measurement: :expired
      ),
      sum(
        "turn.listener.client_inbound_traffic.total.bytes",
        event_name: [:listener, :client],
        measurement: :inbound,
        unit: :byte,
        tags: [:listener_id]
      ),
      counter(
        "turn.listener.client_inbound_traffic.packets.total",
        event_name: [:listener, :client],
        measurement: :inbound,
        tags: [:listener_id]
      ),
      sum(
        "turn.allocations.peer_inbound_traffic.total.bytes",
        event_name: [:allocations, :peer],
        measurement: :inbound,
        unit: :byte
      ),
      counter(
        "turn.allocations.peer_inbound_traffic.packets.total",
        event_name: [:allocations, :peer],
        measurement: :inbound
      ),

      # telemetry poller
      last_value(
        "vm.memory.bytes",
        event_name: [:vm, :memory],
        measurement: :total,
        unit: :byte
      ),
      last_value(
        "vm.run_queue.cpu.length",
        event_name: [:vm, :total_run_queue_lengths],
        measurement: :cpu
      ),
      last_value(
        "vm.run_queue.io.length",
        event_name: [:vm, :total_run_queue_lengths],
        measurement: :io
      )
    ]
  end
end
