defmodule ExTURN.Attribute.ChannelNumber do
  @moduledoc false
  alias ExSTUN.Message.RawAttribute

  @behaviour ExSTUN.Message.Attribute

  @attr_type 0x000C

  @type t() :: %__MODULE__{
          number: integer()
        }

  @enforce_keys [:number]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def from_raw(%RawAttribute{value: <<number::16, 0::16>>}, _msg) do
    {:ok, %__MODULE__{number: number}}
  end

  @impl true
  def from_raw(%RawAttribute{}, _msg) do
    {:error, :invalid_channel_number}
  end
end
