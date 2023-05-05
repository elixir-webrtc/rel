defmodule ExTURN.Attribute.XORRelayedAddress do
  alias ExSTUN.Message.RawAttribute
  alias ExSTUN.Message.Attribute.XORMappedAddress

  @behaviour ExSTUN.Message.Attribute

  @attr_type 0x0016

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
