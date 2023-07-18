defmodule ExTURN.Utils do
  @moduledoc false
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

  @spec get_lifetime(Message.t()) :: {:ok, integer()} | {:error, Message.t()}
  def get_lifetime(msg) do
    case Message.get_attribute(msg, Lifetime) do
      {:ok, %Lifetime{lifetime: lifetime}} ->
        desired_lifetime =
          if lifetime == 0, do: 0, else: max(@default_lifetime, min(lifetime, @max_lifetime))

        {:ok, desired_lifetime}

      nil ->
        {:ok, @default_lifetime}

      {:error, _reason} ->
        {:error, build_error(msg.transaction_id, msg.type.method, 400)}
    end
  end

  @spec build_error(integer(), Method.t(), 300..699, with_attrs?: boolean()) :: Message.t()
  def build_error(t_id, method, code, opts \\ []) do
    with_attrs? = Keyword.get(opts, :with_attrs?, false)
    error_type = %Type{class: :error_response, method: method}

    attrs = [%ErrorCode{code: code}]

    attrs =
      if with_attrs? do
        attrs ++ [%Nonce{value: build_nonce()}, %Realm{value: @domain_name}]
      else
        attrs
      end

    Message.new(t_id, error_type, attrs)
  end

  defp build_nonce() do
    # inspired by https://datatracker.ietf.org/doc/html/rfc7616#section-5.4
    timestamp = System.monotonic_time(:nanosecond)
    hash = :crypto.hash(:sha256, "#{timestamp}:#{@nonce_secret}")
    "#{timestamp} #{hash}" |> :base64.encode()
  end
end
