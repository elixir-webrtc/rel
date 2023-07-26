defmodule ExTURN.Attribute.XORPeerAddress do
  @moduledoc """
  STUN Message Attribute XOR Peer Address

  It is encoded in the same way as XOR Mapped Address.
  """
  @behaviour ExSTUN.Message.Attribute

  alias ExSTUN.Message.Attribute.XORMappedAddress
  alias ExSTUN.Message.RawAttribute

  @attr_type 0x0012

  @type t() :: %__MODULE__{
          port: 0..65_535,
          address: :inet.ip_address()
        }

  @enforce_keys [:port, :address]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def from_raw(%RawAttribute{} = raw_attr, message) do
    case XORMappedAddress.from_raw(raw_attr, message) do
      {:ok, xor_addr} ->
        {:ok, %__MODULE__{port: xor_addr.port, address: xor_addr.address}}

      error ->
        error
    end
  end

  @impl true
  def to_raw(%__MODULE__{} = attribute, message) do
    mapped_address = %XORMappedAddress{
      port: attribute.port,
      address: attribute.address
    }

    raw = XORMappedAddress.to_raw(mapped_address, message)

    %RawAttribute{raw | type: @attr_type}
  end
end
