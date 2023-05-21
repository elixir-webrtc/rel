defmodule ExTURN.App do
  use Application

  require Logger

  def start(_, _) do
    Logger.info("Starting ExTURN")

    listen_ip = Application.get_env(:ex_turn, :listen_ip, {0, 0, 0, 0})
    listen_port = Application.get_env(:ex_turn, :listen_port, 7878)

    listener_child_spec = %{
      id: ExTURN.Listener,
      start: {Task, :start, [ExTURN.Listener, :listen, [listen_ip, listen_port]]}
    }

    children = [
      {TelemetryMetricsPrometheus, metrics: metrics()},
      {DynamicSupervisor, strategy: :one_for_one, name: ExTURN.AllocationSupervisor},
      {Registry, keys: :unique, name: Registry.Allocations},
      listener_child_spec
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end

  defp metrics() do
    import Telemetry.Metrics

    [
      last_value("listener.in_bitrate", tags: [:listener_id]),
      last_value("listener.out_bitrate", tags: [:listener_id]),
      last_value("allocation.in_bitrate", tags: [:allocation_id]),
      last_value("allocation.out_bitrate", tags: [:allocation_id])
    ]
  end
end
