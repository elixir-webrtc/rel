# Rel

[![CI](https://img.shields.io/github/actions/workflow/status/elixir-webrtc/rel/ci.yml?logo=github&label=CI)](https://github.com/elixir-webrtc/rel/actions/workflows/ci.yml)
[![Deployment](https://img.shields.io/github/actions/workflow/status/elixir-webrtc/rel/build_deploy.yml?logo=github&label=Deployment)](https://github.com/elixir-webrtc/rel/actions/workflows/build_deploy.yml)
[![Package](https://ghcr-badge.egpl.dev/elixir-webrtc/rel/latest_tag?trim=major&label=latest)](https://github.com/elixir-webrtc/rel/pkgs/container/rel)

TURN server in pure Elixir.

Aims to implement:
- RFC 5389: [Session Traversal Utilities for NAT (STUN)](https://datatracker.ietf.org/doc/html/rfc5389)
- RFC 5766: [Traversal Using Relays around NAT (TURN): Relay Extensions to Session Traversal Utilities for NAT (STUN)](https://datatracker.ietf.org/doc/html/rfc5766)
- RFC 6156: [Traversal Using Relays around NAT (TURN) Extension for IPv6](https://datatracker.ietf.org/doc/html/rfc6156#autoid-7)

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

## Installation and running

1. From source

```console
git clone https://github.com/elixir-webrtc/rel.git
cd rel
mix deps.get
mix run --no-halt
```

2. In Docker

```console
docker run --network=host ghcr.io/elixir-webrtc/rel:latest
```

## Features and configuration

Rel exposes Prometheus metrics endpoint (by default `http://127.0.0.1:9568/metrics`).

Rel supports authentication described in [A REST API For Access To TURN Services](https://datatracker.ietf.org/doc/html/draft-uberti-rtcweb-turn-rest-00#section-2.2).
By default available under `http://127.0.0.1:4000/`. Example request would be `POST http://127.0.0.1:40000/?service=turn&username=johnsmith`.
Key query parameter currently is not supported.

Rel is configured via environment variables. All of the possible options are described in [sample env file](./sample.env).
