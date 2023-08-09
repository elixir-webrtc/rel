FROM hexpm/elixir:1.15.4-erlang-26.0.2-alpine-3.18.2 as build

RUN apk add --no-cache --update git

WORKDIR /app

RUN mix local.hex --force && \
  mix local.rebar --force

ENV MIX_ENV=prod

COPY mix.exs mix.lock ./
RUN mix deps.get --only $MIX_ENV

COPY config/config.exs config/${MIX_ENV}.exs config/
RUN mix deps.compile

COPY lib lib
RUN mix compile

COPY config/runtime.exs config/

RUN mix release

FROM alpine:3.18.2 as app

RUN apk add --no-cache --update libncursesw openssl libstdc++

WORKDIR /app

COPY --from=build /app/_build/prod/rel/ex_turn ./

CMD ["bin/ex_turn", "start"]
