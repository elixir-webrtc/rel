defmodule ExTURN.Attribute.EvenPort do
  @moduledoc false
  alias ExSTUN.Message.RawAttribute

  @behaviour ExSTUN.Message.Attribute

  @attr_type 0x0018

  @type t() :: %__MODULE__{
          r: boolean()
        }

  @enforce_keys [:r]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def from_raw(%RawAttribute{} = raw_attr, _message) do
    decode(raw_attr.value)
  end

  defp decode(<<1::1, 0::7>>), do: {:ok, %__MODULE__{r: true}}
  defp decode(<<0::1, 0::7>>), do: {:ok, %__MODULE__{r: false}}
  defp decode(_other), do: {:error, :invalid_even_port}
end
