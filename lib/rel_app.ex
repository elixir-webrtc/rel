defmodule Rel.App do
  @moduledoc false
  use Application

  require Logger

  @version Mix.Project.config()[:version]

  @impl true
  def start(_, _) do
    Logger.info("Starting Rel v#{@version}")

    auth_provider_ip = Application.fetch_env!(:rel, :auth_provider_ip)
    auth_provider_port = Application.fetch_env!(:rel, :auth_provider_port)
    use_tls? = Application.fetch_env!(:rel, :auth_provider_use_tls?)
    keyfile = Application.fetch_env!(:rel, :keyfile)
    certfile = Application.fetch_env!(:rel, :certfile)

    metrics_ip = Application.fetch_env!(:rel, :metrics_ip)
    metrics_port = Application.fetch_env!(:rel, :metrics_port)

    scheme_opts =
      if use_tls? do
        [
          scheme: :https,
          certfile: certfile,
          keyfile: keyfile
        ]
      else
        [scheme: :http]
      end

    children = [
      Rel.Supervisor,
      {TelemetryMetricsPrometheus,
       metrics: metrics(), plug_cowboy_opts: [ip: metrics_ip, port: metrics_port]},
      {Bandit,
       [plug: Rel.AuthProvider, ip: auth_provider_ip, port: auth_provider_port] ++ scheme_opts}
    ]

    Logger.info(
      "Starting Prometheus metrics endpoint at: http://#{:inet.ntoa(metrics_ip)}:#{metrics_port}/metrics"
    )

    Logger.info(
      "Starting credentials endpoint at: #{if(use_tls?, do: ~c"https", else: ~c"http")}://#{:inet.ntoa(auth_provider_ip)}:#{auth_provider_port}/"
    )

    Supervisor.start_link(children, strategy: :one_for_one)
  end

  defp metrics() do
    import Telemetry.Metrics

    [
      last_value("listener.in_bitrate", tags: [:listener_id]),
      last_value("allocation.in_bitrate", tags: [:allocation_id]),
      last_value("allocation.out_bitrate", tags: [:allocation_id]),

      # telemetry poller
      last_value("vm.memory.total", unit: :byte),
      last_value("vm.total_run_queue_lengths.total"),
      last_value("vm.total_run_queue_lengths.cpu"),
      last_value("vm.total_run_queue_lengths.io")
    ]
  end
end
