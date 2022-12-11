defmodule ExTURN.STUN.Attribute.AdditionalAddressFamily do
  alias ExStun.Message

  @attr_type 0x8000

  @type t() :: %__MODULE__{
          family: :ipv4 | :ipv6
        }

  @enforce_keys [:family]
  defstruct @enforce_keys

  @spec get_from_message(Message.t()) ::
          {:ok, t()} | {:error, :invalid_additional_address_family} | nil
  def get_from_message(message) do
    case Message.get_attribute(message, @attr_type) do
      nil -> nil
      raw_attr -> decode(raw_attr.value)
    end
  end

  defp decode(<<0x01, 0, 0, 0>>), do: {:ok, %__MODULE__{family: :ipv4}}
  defp decode(<<0x02, 0, 0, 0>>), do: {:ok, %__MODULE__{family: :ipv6}}
  defp decode(_other), do: {:error, :invalid_additional_address_family}
end
