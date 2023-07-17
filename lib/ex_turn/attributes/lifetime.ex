defmodule ExTURN.Attribute.Lifetime do
  @moduledoc false
  alias ExSTUN.Message.RawAttribute

  @attr_type 0x000D

  @behaviour ExSTUN.Message.Attribute

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
end
