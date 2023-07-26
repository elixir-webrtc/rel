defmodule ExTURN.Attribute.Lifetime do
  @moduledoc false
  @behaviour ExSTUN.Message.Attribute

  alias ExSTUN.Message.RawAttribute

  @attr_type 0x000D

  @type t() :: %__MODULE__{
          lifetime: integer()
        }

  @enforce_keys [:lifetime]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def to_raw(%__MODULE__{} = attr, _msg) do
    %RawAttribute{type: @attr_type, value: <<attr.lifetime::32>>}
  end

  @impl true
  def from_raw(%RawAttribute{} = raw_attr, _msg) do
    decode(raw_attr.value)
  end

  defp decode(<<lifetime::32>>) do
    {:ok, %__MODULE__{lifetime: lifetime}}
  end

  defp decode(_data), do: {:error, :invalid_lifetime}
end
