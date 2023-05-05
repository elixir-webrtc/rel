defmodule ExTURN.Attribute.RequestedTransport do
  alias ExSTUN.Message.RawAttribute

  @behaviour ExSTUN.Message.Attribute

  @attr_type 0x0019

  @type t() :: %__MODULE__{
          protocol: :udp | :tcp
        }

  @enforce_keys [:protocol]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def from_raw(%RawAttribute{} = raw_attr, _message) do
    decode(raw_attr.value)
  end

  defp decode(<<17, 0, 0, 0>>), do: {:ok, %__MODULE__{protocol: :udp}}
  defp decode(<<6, 0, 0, 0>>), do: {:ok, %__MODULE__{protocol: :tcp}}
  defp decode(_other), do: {:error, :invalid_requested_transport}
end
