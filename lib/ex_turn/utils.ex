defmodule ExTURN.Utils do
  @moduledoc false
  require Logger

  alias ExSTUN.Message
  alias ExSTUN.Message.Method
  alias ExSTUN.Message.Type
  alias ExSTUN.Message.Attribute.{ErrorCode, Nonce, Realm}

  alias ExTURN.Attribute.Lifetime

  @domain_name Application.compile_env!(:ex_turn, :domain_name)
  @nonce_secret Application.compile_env!(:ex_turn, :nonce_secret)

  # TODO: proper lifetime values
  @default_lifetime 100
  @max_lifetime 3600

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
    {log_msg, code, with_attrs?} = translate_error(reason)
    error_type = %Type{class: :error_response, method: method}

    attrs = [%ErrorCode{code: code}]

    attrs =
      if with_attrs? do
        attrs ++ [%Nonce{value: build_nonce()}, %Realm{value: @domain_name}]
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
    timestamp = System.monotonic_time(:nanosecond)
    hash = :crypto.hash(:sha256, "#{timestamp}:#{@nonce_secret}")
    "#{timestamp} #{hash}" |> :base64.encode()
  end

  defp translate_error(reason) do
    case reason do
      :allocation_not_found ->
        {"Allocation mismatch: allocation does not exist", 437, false}

      :allocation_exists ->
        {"Allocation mismatch: allocation already exists", 437, false}

      :requested_transport_tcp ->
        {"Unsupported REQUESTED-TRANSPORT: TCP", 442, false}

      :invalid_requested_transport ->
        {"No or malformed REQUESTED-TRANSPORT", 400, false}

      :invalid_even_port ->
        {"Failed to decode EVEN-PORT", 400, false}

      :invalid_requested_address_family ->
        {"Failed to decode REQUESTED-ADDRESS-FAMILY", 400, false}

      :reservation_token_with_others ->
        {"RESERVATION-TOKEN and (EVEN-PORT|REQUESTED-FAMILY) in the message", 400, false}

      :reservation_token_unsupported ->
        {"RESERVATION-TOKEN unsupported", 400, false}

      :invalid_reservation_token ->
        {"Failed to decode RESERVATION-TOKEN", 400, false}

      :requested_address_family_unsupported ->
        {"REQUESTED-ADDRESS-FAMILY with IPv6 unsupported", 440, false}

      :even_port_unsupported ->
        {"EVEN-PORT unsupported", 400, false}

      :out_of_ports ->
        {"No available ports left", 508, false}

      :invalid_lifetime ->
        {"Failed to decode LIFETIME", 400, false}

      :invalid_message_integrity ->
        {"Failed do decode MESSAGE-INTEGRITY", 400, false}

      :no_message_integrity ->
        {"No message integrity attribute", 401, true}

      :auth_attrs_missing ->
        {"No username, nonce or realm attribute", 400, false}

      :invalid_username_timestamp ->
        {"Username timestamp expired", 401, true}

      :invalid_username ->
        {"Username differs from the one used previously", 441, true}

      :stale_nonce ->
        {"Stale nonce", 438, true}

      :no_xor_peer_address_attribute ->
        {"No XOR-PEER-ADDRESS attribute", 400, false}

      :invalid_xor_peer_address ->
        {"Failed to decode XOR-PEER-ADDRESS", 400, false}

      :no_data_attribute ->
        {"No DATA attribute", 400, false}

      :invalid_data ->
        {"Failed to decode DATA", 400, false}

      :no_channel_number_attribute ->
        {"No CHANNEL-NUMBER attribute", 400, false}

      :invalid_channel_number ->
        {"Failed to decode CHANNEL-NUMBER", 400, false}

      :channel_number_out_of_range ->
        {"Channel number is out of allowed range", 400, false}

      :channel_number_bound ->
        {"Channel number is already bound", 400, false}

      :addr_bound_to_channel ->
        {"Address is already bound to channel", 400, false}

      other ->
        Logger.error("Unsupported error type: #{other}")
        {"", 500}
    end
  end
end
