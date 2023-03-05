defmodule ExTURN.STUN.Attribute.Data do
  alias ExStun.Message

  @attr_type 0x0013

  @type t() :: %__MODULE__{
          value: binary()
        }

  @enforce_keys [:value]
  defstruct @enforce_keys

  @spec get_from_message(Message.t()) :: {:ok, t()} | {:error, :data} | nil
  def get_from_message(message) do
    case Message.get_attribute(message, @attr_type) do
      nil -> nil
      raw_attr -> {:ok, %__MODULE__{value: raw_attr}}
    end
  end
end

defimpl ExStun.Message.Attribute, for: ExTURN.STUN.Attribute.Data do
  alias ExTURN.STUN.Attribute.Data
  alias ExStun.Message.RawAttribute

  @attr_type 0x0013

  def to_raw_attribute(%Data{value: value}, _msg) do
    %RawAttribute{type: @attr_type, value: value}
  end
end
