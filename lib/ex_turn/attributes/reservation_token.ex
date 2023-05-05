defmodule ExTURN.Attribute.ReservationToken do
  alias ExSTUN.Message.RawAttribute

  @behaviour ExSTUN.Message.Attribute

  @attr_type 0x0022

  @type t() :: %__MODULE__{
          token: binary()
        }

  @enforce_keys [:token]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def from_raw(%RawAttribute{} = raw_attr, _message) do
    decode(raw_attr.value)
  end

  defp decode(<<token::binary-size(8)>>), do: {:ok, %__MODULE__{token: token}}
  defp decode(_other), do: {:error, :invalid_reservation_token}
end
