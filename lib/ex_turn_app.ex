defmodule ExTURN.App do
  @moduledoc false
  use Application

  require Logger

  @impl true
  def start(_, _) do
    Logger.info("Starting ExTURN...")

    listen_ip = Application.fetch_env!(:ex_turn, :listen_ip)
    listen_port = Application.fetch_env!(:ex_turn, :listen_port)
    auth_provider_port = Application.fetch_env!(:ex_turn, :auth_provider_port)
    use_tls? = Application.fetch_env!(:ex_turn, :auth_provider_use_tls?)

    listener_child_spec = %{
      id: ExTURN.Listener,
      start: {Task, :start, [ExTURN.Listener, :listen, [listen_ip, listen_port]]}
    }

    # TODO
    scheme = if(use_tls?, do: :https, else: :http)

    children = [
      {TelemetryMetricsPrometheus, metrics: metrics()},
      {DynamicSupervisor, strategy: :one_for_one, name: ExTURN.AllocationSupervisor},
      {Registry, keys: :unique, name: Registry.Allocations},
      {Bandit,
       plug: ExTURN.AuthProvider, scheme: scheme, ip: listen_ip, port: auth_provider_port},
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
