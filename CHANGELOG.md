# Changelog

## 1.1.0

- Standalone, `port-forwarder.exe` now opens a native window (Slint) instead of a browser
  page: the rules with their status and counters, the same editor and checks as the page
  (every change still goes through the plugin's own API), Chinese and English, light and dark.
  Closing the window stops all forwarding. Hosted in Ghost, nothing changes: Ghost shows the
  management page.
- `--web` opens the management page in the browser instead of the window (the old default);
  `--no-browser` is unchanged (the page only, nothing opened).
- Building needs a Rust toolchain (1.92 or later): Slint 1.18.1 is compiled from source and
  linked statically, so a release is still one exe. Slint is used under the Slint Royalty-free
  License 2.0 (AboutSlint in Help > About); its notices and those of its Rust dependencies are
  in THIRD_PARTY_NOTICES.txt.
- Fixed: the management page answered a mistyped remote host with "Wrong host name in the
  request" instead of the rule's own message. The page server's code for a wrong `Host`
  header is now `bad_host_header`; `bad_host` is only the rule's.

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
