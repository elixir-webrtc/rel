defmodule ExTURN.STUN.Attribute.EvenPort do
  alias ExStun.Message

  @attr_type 0x0018

  @type t() :: %__MODULE__{
          r: boolean()
        }

  @enforce_keys [:r]
  defstruct @enforce_keys

  @spec get_from_message(Message.t()) :: {:ok, t()} | {:error, :invalid_even_port} | nil
  def get_from_message(message) do
    case Message.get_attribute(message, @attr_type) do
      nil -> nil
      raw_attr -> decode(raw_attr.value)
    end
  end

  defp decode(<<1::1, 0::7>>), do: {:ok, %__MODULE__{r: true}}
  defp decode(<<0::1, 0::7>>), do: {:ok, %__MODULE__{r: false}}
  defp decode(_other), do: {:error, :invalid_even_port}
end
