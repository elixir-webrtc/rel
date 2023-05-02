defmodule ExTURN.STUN.Attribute.ChannelNumber do
  alias ExStun.Message.RawAttribute
  alias ExStun.Message

  @attr_type 0x000C

  @type t() :: %__MODULE__{
          number: integer()
        }

  @enforce_keys [:number]
  defstruct @enforce_keys

  @spec get_from_message(Message.t()) :: {:ok, t()} | {:error, :invalid_channel_number} | nil
  def get_from_message(message) do
    case Message.get_attribute(message, @attr_type) do
      nil ->
        nil

      %RawAttribute{value: <<number::16, 0::16>>} ->
        {:ok, %__MODULE__{number: number}}

      _other ->
        {:error, :invalid_channel_number}
    end
  end
end

defimpl ExStun.Message.Attribute, for: ExTURN.STUN.Attribute.ChannelNumber do
  alias ExTURN.STUN.Attribute.Data
  alias ExStun.Message.RawAttribute

  @attr_type 0x000C

  def to_raw_attribute(%Data{value: value}, _msg) do
    %RawAttribute{type: @attr_type, value: value}
  end
end
