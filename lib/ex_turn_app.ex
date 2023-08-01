defmodule ExTURN.App do
  @moduledoc false
  use Application

  require Logger

  @impl true
  def start(_, _) do
    Logger.info("Starting ExTURN...")

    listen_ip = Application.fetch_env!(:ex_turn, :listen_ip)
    listen_port = Application.fetch_env!(:ex_turn, :listen_port)

    auth_provider_ip = Application.fetch_env!(:ex_turn, :auth_provider_ip)
    auth_provider_port = Application.fetch_env!(:ex_turn, :auth_provider_port)
    use_tls? = Application.fetch_env!(:ex_turn, :auth_provider_use_tls?)
    keyfile = Application.fetch_env!(:ex_turn, :keyfile)
    certfile = Application.fetch_env!(:ex_turn, :certfile)

    metrics_ip = Application.fetch_env!(:ex_turn, :metrics_ip)
    metrics_port = Application.fetch_env!(:ex_turn, :metrics_port)

    listener_child_spec = %{
      id: ExTURN.Listener,
      start: {Task, :start, [ExTURN.Listener, :listen, [listen_ip, listen_port]]}
    }

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
      {TelemetryMetricsPrometheus, metrics: metrics(), plug_cowboy_opts: [ip: metrics_ip, port: metrics_port]},
      {DynamicSupervisor, strategy: :one_for_one, name: ExTURN.AllocationSupervisor},
      {Registry, keys: :unique, name: Registry.Allocations},
      {Bandit,
       [plug: ExTURN.AuthProvider, ip: auth_provider_ip, port: auth_provider_port] ++ scheme_opts},
      listener_child_spec
    ]

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
