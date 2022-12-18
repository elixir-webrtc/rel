defmodule ExTURN.STUN.Attribute.Lifetime do
  @type t() :: %__MODULE__{
          lifetime: integer()
        }

  @enforce_keys [:lifetime]
  defstruct @enforce_keys
end

defimpl ExStun.Message.Attribute, for: ExTURN.STUN.Attribute.Lifetime do
  alias ExStun.Message.RawAttribute

  @attr_type 0x000D

  def to_raw_attribute(attr, _msg) do
    %RawAttribute{type: @attr_type, value: <<attr.lifetime::32>>}
  end
end
