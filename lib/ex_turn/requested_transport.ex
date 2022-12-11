defmodule ExTURN.STUN.Attribute.RequestedTransport do
  alias ExStun.Message

  @attr_type 0x0019

  @type t() :: %__MODULE__{
          protocol: :udp | :tcp
        }

  @enforce_keys [:protocol]
  defstruct @enforce_keys

  @spec get_from_message(Message.t()) :: {:ok, t()} | {:error, :invalid_requested_transport} | nil
  def get_from_message(message) do
    case Message.get_attribute(message, @attr_type) do
      nil -> nil
      raw_attr -> decode(raw_attr.value)
    end
  end

  defp decode(<<17, 0, 0, 0>>), do: {:ok, %__MODULE__{protocol: :udp}}
  defp decode(<<6, 0, 0, 0>>), do: {:ok, %__MODULE__{protocol: :tcp}}
end
