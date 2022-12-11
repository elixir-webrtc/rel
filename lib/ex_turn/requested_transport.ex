defmodule ExTURN.STUN.Attribute.RequestedTransport do
  alias ExStun.Message

  @attr_type 0x0025

  @type t() :: %__MODULE__{
          protocol: :udp
        }

  @enforce_keys [:protocol]
  defstruct @enforce_keys

  @spec get_from_message(Message.t()) :: t() | nil
  def get_from_message(message) do
    case Message.get_attribute(message, @attr_type) do
      nil -> nil
      raw_attr -> decode(raw_attr.value)
    end
  end

  defp decode(<<17, 0, 0, 0>>) do
    %__MODULE__{protocol: :udp}
  end
end
