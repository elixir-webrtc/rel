defmodule ExTURN.App do
  use Application

  require Logger

  def start(_, _) do
    Logger.info("Starting ExTURN")

    children = [
      ExTURN,
      {Task.Supervisor, name: ExTURN.ListenerSupervisor},
      {Task.Supervisor, name: ExTURN.ClientSupervisor}
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
