defmodule ExTURN.STUN.Attribute.ReservationToken do
  alias ExStun.Message

  @attr_type 0x0022

  @type t() :: %__MODULE__{
          token: binary()
        }

  @enforce_keys [:token]
  defstruct @enforce_keys

  @spec get_from_message(Message.t()) :: {:ok, t()} | {:error, :invalid_reservation_token} | nil
  def get_from_message(message) do
    case Message.get_attribute(message, @attr_type) do
      nil -> nil
      raw_attr -> decode(raw_attr.value)
    end
  end

  defp decode(<<token::binary-size(8)>>), do: {:ok, %__MODULE__{token: token}}
  defp decode(_other), do: {:error, :invalid_reservation_token}
end
