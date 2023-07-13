defmodule ExTURN.Attribute.AdditionalAddressFamily do
  @moduledoc false
  alias ExSTUN.Message.RawAttribute

  @behaviour ExSTUN.Message.Attribute

  @attr_type 0x8000

  @type t() :: %__MODULE__{
          family: :ipv4 | :ipv6
        }

  @enforce_keys [:family]
  defstruct @enforce_keys

  @impl true
  def type(), do: @attr_type

  @impl true
  def from_raw(%RawAttribute{} = raw_attr, _msg) do
    decode(raw_attr.value)
  end

  defp decode(<<0x01, 0, 0, 0>>), do: {:ok, %__MODULE__{family: :ipv4}}
  defp decode(<<0x02, 0, 0, 0>>), do: {:ok, %__MODULE__{family: :ipv6}}
  defp decode(_other), do: {:error, :invalid_additional_address_family}
end
