defmodule ExTURN.Attribute.XORRelayedAddress do
  @moduledoc false
  @behaviour ExSTUN.Message.Attribute

  alias ExSTUN.Message.Attribute.XORMappedAddress
  alias ExSTUN.Message.RawAttribute

  @attr_type 0x0016

  @type t() :: %__MODULE__{
          port: 0..65_535,
          address: :inet.ip_address()
        }

  @enforce_keys [:port, :address]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

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
