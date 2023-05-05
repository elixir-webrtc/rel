defmodule ExTURN.Attribute.XORPeerAddress do
  @moduledoc """
  STUN Message Attribute XOR Peer Address

  It is encoded in the same way as XOR Mapped Address.
  """
  alias ExSTUN.Message.RawAttribute
  alias ExSTUN.Message.Attribute.XORMappedAddress

  @behaviour ExSTUN.Message.Attribute

  @attr_type 0x0012

  @type t() :: %__MODULE__{
          family: :ipv4 | :ipv6,
          port: 0..65_535,
          address: :inet.ip_address()
        }

  @enforce_keys [:family, :port, :address]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def from_raw(%RawAttribute{} = raw_attr, message) do
    case XORMappedAddress.from_raw(raw_attr, message) do
      {:ok, xor_addr} ->
        {:ok,
         %__MODULE__{family: xor_addr.family, port: xor_addr.port, address: xor_addr.address}}

      error ->
        error
    end
  end

  @impl true
  def to_raw(%__MODULE__{} = attribute, message) do
    mapped_address = %XORMappedAddress{
      family: attribute.family,
      port: attribute.port,
      address: attribute.address
    }

    raw = XORMappedAddress.to_raw(mapped_address, message)

    %RawAttribute{raw | type: @attr_type}
  end
end
