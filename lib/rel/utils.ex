defmodule Rel.Utils do
  @moduledoc false
  require Logger

  alias ExSTUN.Message
  alias ExSTUN.Message.Method
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{ErrorCode, Nonce, Realm}

  alias Rel.Attribute.Lifetime

  @default_lifetime Application.compile_env!(:rel, :default_allocation_lifetime)
  @max_lifetime Application.compile_env!(:rel, :max_allocation_lifetime)

  @spec get_lifetime(Message.t()) :: {:ok, integer()} | {:error, :invalid_lifetime}
  def get_lifetime(msg) do
    case Message.get_attribute(msg, Lifetime) do
      {:ok, %Lifetime{lifetime: lifetime}} ->
        desired_lifetime =
          if lifetime == 0, do: 0, else: max(@default_lifetime, min(lifetime, @max_lifetime))

        {:ok, desired_lifetime}

      nil ->
        {:ok, @default_lifetime}

      {:error, _reason} ->
        {:error, :invalid_lifetime}
    end
  end

  @spec build_error(atom(), integer(), Method.t()) ::
          {response :: binary(), log_msg :: String.t()}
  def build_error(reason, t_id, method) do
    domain = Application.fetch_env!(:rel, :domain)
    {log_msg, code, with_attrs?} = translate_error(reason)
    error_type = %Type{class: :error_response, method: method}

    attrs = [%ErrorCode{code: code}]

    attrs =
      if with_attrs? do
        attrs ++ [%Nonce{value: build_nonce()}, %Realm{value: domain}]
      else
        attrs
      end

    response =
      t_id
      |> Message.new(error_type, attrs)
      |> Message.encode()

    {response, log_msg <> ", rejected"}
  end

  defp build_nonce() do
    # inspired by https://datatracker.ietf.org/doc/html/rfc7616#section-5.4
    nonce_secret = Application.fetch_env!(:rel, :nonce_secret)
    timestamp = System.monotonic_time(:nanosecond)
    hash = :crypto.hash(:sha256, "#{timestamp}:#{nonce_secret}")
    "#{timestamp} #{hash}" |> :base64.encode()
  end

  defp translate_error(:allocation_not_found),
    do: {"Allocation mismatch: allocation does not exist", 437, false}

  defp translate_error(:allocation_exists),
    do: {"Allocation mismatch: allocation already exists", 437, false}

  defp translate_error(:requested_transport_tcp),
    do: {"Unsupported REQUESTED-TRANSPORT: TCP", 442, false}

  defp translate_error(:invalid_requested_transport),
    do: {"No or malformed REQUESTED-TRANSPORT", 400, false}

  defp translate_error(:invalid_even_port),
    do: {"Failed to decode EVEN-PORT", 400, false}

  defp translate_error(:invalid_requested_address_family),
    do: {"Failed to decode REQUESTED-ADDRESS-FAMILY", 400, false}

  defp translate_error(:reservation_token_with_others),
    do: {"RESERVATION-TOKEN and (EVEN-PORT|REQUESTED-FAMILY) in the message", 400, false}

  defp translate_error(:reservation_token_unsupported),
    do: {"RESERVATION-TOKEN unsupported", 400, false}

  defp translate_error(:invalid_reservation_token),
    do: {"Failed to decode RESERVATION-TOKEN", 400, false}

  defp translate_error(:requested_address_family_unsupported),
    do: {"REQUESTED-ADDRESS-FAMILY with IPv6 unsupported", 440, false}

  defp translate_error(:even_port_unsupported),
    do: {"EVEN-PORT unsupported", 400, false}

  defp translate_error(:out_of_ports),
    do: {"No available ports left", 508, false}

  defp translate_error(:invalid_lifetime),
    do: {"Failed to decode LIFETIME", 400, false}

  defp translate_error(:no_matching_message_integrity),
    do: {"Auth failed, invalid MESSAGE-INTEGRITY", 400, false}

  defp translate_error(:no_message_integrity),
    do: {"No message integrity attribute", 401, true}

  defp translate_error(:auth_attrs_missing),
    do: {"No username, nonce or realm attribute", 400, false}

  defp translate_error(:invalid_username_timestamp),
    do: {"Username timestamp expired", 401, true}

  defp translate_error(:invalid_username),
    do: {"Username differs from the one used previously", 441, true}

  defp translate_error(:stale_nonce),
    do: {"Stale nonce", 438, true}

  defp translate_error(:no_xor_peer_address_attribute),
    do: {"No XOR-PEER-ADDRESS attribute", 400, false}

  defp translate_error(:invalid_xor_peer_address),
    do: {"Failed to decode XOR-PEER-ADDRESS", 400, false}

  defp translate_error(:no_data_attribute),
    do: {"No DATA attribute", 400, false}

  defp translate_error(:invalid_data),
    do: {"Failed to decode DATA", 400, false}

  defp translate_error(:no_channel_number_attribute),
    do: {"No CHANNEL-NUMBER attribute", 400, false}

  defp translate_error(:invalid_channel_number),
    do: {"Failed to decode CHANNEL-NUMBER", 400, false}

  defp translate_error(:channel_number_out_of_range),
    do: {"Channel number is out of allowed range", 400, false}

  defp translate_error(:channel_number_bound),
    do: {"Channel number is already bound", 400, false}

  defp translate_error(:addr_bound_to_channel),
    do: {"Address is already bound to channel", 400, false}

  defp translate_error(other) do
    Logger.error("Unsupported error type: #{other}")
    {"", 500}
  end
end
