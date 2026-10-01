# Changelog

## 1.0.0

First release.

- TCP and UDP port forwarding rules, up to 64, each with a listen address and port, a remote
  host and port, and an egress: direct, Ghost's active upstream node, or a chosen node.
- Through a node, Ghost opens the connection and hands it over (`upstream.connect`, Ghost
  1.2.1 or later); a refused or failed tunnel closes the client connection and is never
  retried directly. UDP through a node needs the node's UDP relay enabled and verified in Ghost.
- A management page in Ghost's plugin center: add, edit, enable, disable and delete rules;
  status, connections, bytes and the last error per rule; Chinese and English, light and dark.
- Listening on a non-loopback address requires an explicit acknowledgement.
- Start, stop and rule changes go to Ghost's application log (`log.write`); client addresses
  and per-connection destinations are never logged.
- Standalone mode without Ghost (direct rules only), with `--data-dir` and `--no-browser`.
