# Rel

[![CI](https://img.shields.io/github/actions/workflow/status/elixir-webrtc/rel/ci.yml?logo=github&label=CI)](https://github.com/elixir-webrtc/rel/actions/workflows/ci.yml)
[![Deployment](https://img.shields.io/github/actions/workflow/status/elixir-webrtc/rel/build_deploy.yml?logo=github&label=Deployment)](https://github.com/elixir-webrtc/rel/actions/workflows/build_deploy.yml)
[![Package](https://ghcr-badge.egpl.dev/elixir-webrtc/rel/latest_tag?trim=major&label=latest)](https://github.com/elixir-webrtc/rel/pkgs/container/rel)

TURN server in pure Elixir.

Aims to implement:
- [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766)
- [RFC 6156](https://datatracker.ietf.org/doc/html/rfc6156#autoid-7)

This project is in early stage of development and some of the features described in the RFCs might be missing.
Expect breaking changes.

Supports authentication described in [A REST API For Access To TURN Services](https://datatracker.ietf.org/doc/html/draft-uberti-rtcweb-turn-rest-00#section-2.2).

## Public deployment

If you're in need of TURN server for testing purposes, feel free to use this Rel public deployment at `turn.bigcow.ovh`. 

In case of any irregularities or bugs, please open an issue with description of the problem. 
DO NOT use this deployment in production, as it's intended to be an aid in developement only.

To obtain a set of credentials, use the built-in credentials mechanism. It does not require any authentication, but the credentials must be refreshed after 3 hours if not used.

```console
$ curl -X POST "https://turn.bigcow.ovh/?service=turn&username=johnsmith"
{"password":"l6hs9SzUgudFeb5XjrfCfOWKeOQ=","ttl":1728,"uris":["turn:167.235.241.140:3478?transport=udp"],"username":"1691574817:johnsmith"}⏎
```

Use the obtained credentials in e.g. WebRTC's `RTCPeerConnection`:

```js
pc = new RTCPeerConnection({
  iceServers: [
    {
      credential: "l6hs9SzUgudFeb5XjrfCfOWKeOQ=",
      urls: "turn:167.235.241.140:3478?transport=udp", 
      username: "1691574817:johnsmith" 
    }
  ]
});
```

## Installation

1. From source

```console
git clone https://github.com/elixir-webrtc/rel.git
cd rel
mix deps.get
mix run --no-halt
```

2. In Docker

```console
docker run ghcr.io/elixir-webrtc/rel:latest
```

## Features and configuration

Currently, Rel is configured via environment variables.

### TURN server

Rel by default listens on `0.0.0.0:3478/UDP` for TURN traffic. This can be configured via `LISTEN_IP` and `LISTEN_PORT`.

```console
LISTEN_IP=0.0.0.0
LISTEN_PORT=3478
```

`EXTERNAL_LISTEN_IP` is the IP address at which Rel is visible to clients. By default, Rel will try to guess the address
based on active network interfaces, but this must be set explicitly when e.g. using Docker without `--network host`.

```console
EXTERNAL_LISTEN_IP=167.235.241.140
```

By default, Rel will use the same addresses (`RELAY_IP == LISTEN_IP and EXTERNAL_RELAY_IP == EXTERNAL_LISTEN_IP`) to open allocations, but this
can be set to something else:

```console
RELAY_IP=0.0.0.0
EXTERNAL_RELAY_IP=167.235.241.140
```

Rel will try to open relay addresses in `49_152 - 65_535` port range, but this can be changed. `RELAY_PORT_END` must be greater than `RELAY_PORT_START`.

```console
RELAY_PORT_START=35000
RELAY_PORT_END=45000
```

Remember to use the `REALM` variable specific to your deployment. It's used in `REALM` STUN attributes. See
[this section of RFC 2617](https://datatracker.ietf.org/doc/html/rfc2617#section-3.2.1) to learn about appropriate values for `REALM` attribute.

```console
REALM=my-amazing-turn.com
```

You can configure the number of running `listener` processes. By default, it is equal to number of running Erlang VM schedulers:

```console
LISTENER_COUNT=8
```

### Auth

Auth Provider is an HTTP endpoint that provides credentials required by *A REST API For Access To TURN Services*.
By default it is available at `http://127.0.0.1:4000/`, but the address, encryption and CORS can be configured:

```console
AUTH_IP=127.0.0.1
AUTH_PORT=4000
AUTH_USE_TLS=false
AUTH_KEYFILE=./rel.key
AUTH_CERTFILE./rel.cert
AUTH_ALLOW_CORS=false
```

### Metrics

By default, Rel provides Prometheus metrics at `http://127.0.0.1:9578/metrics`. The address can be configured:

```console
METRICS_IP=127.0.0.1
METRICS_PORT=9568
```

