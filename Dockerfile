FROM hexpm/elixir:1.14.4-erlang-25.3.2-alpine-3.18.0 as build

RUN apk add --no-cache --update git

WORKDIR /app

RUN mix local.hex --force && \
  mix local.rebar --force

ENV MIX_ENV=prod

COPY mix.exs mix.lock ./
RUN mix deps.get --only $MIX_ENV

COPY config/config.exs config/${MIX_ENV}.exs config
RUN mix deps.compile

COPY lib lib
RUN mix compile

COPY config/runtime.exs config/

RUN mix release

FROM alpine:3.18.0 as app

WORKDIR /app

RUN apk add --no-cache --update libncursesw openssl libstdc++

COPY --from=build /app/_build/prod/rel/ex_turn ./

CMD ["bin/ex_turn", "start"]
