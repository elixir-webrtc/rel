defmodule ExTURN.STUN.Attribute.XORRelayedAddress do
  @type t() :: %__MODULE__{
          family: :ipv4 | :ipv6,
          port: 0..65_535,
          address: :inet.ip_address()
        }

  @enforce_keys [:family, :port, :address]
  defstruct @enforce_keys
end

defimpl ExStun.Message.Attribute, for: ExTURN.STUN.Attribute.XORRelayedAddress do
  alias ExStun.Message.Attribute
  alias ExStun.Message.Attribute.XORMappedAddress
  alias ExStun.Message.RawAttribute

  @attr_type 0x0016

  def to_raw_attribute(attribute, message) do
    mapped_address = %XORMappedAddress{
      family: attribute.family,
      port: attribute.port,
      address: attribute.address
    }

    raw = Attribute.to_raw_attribute(mapped_address, message)

    %RawAttribute{raw | type: @attr_type}
  end
end
