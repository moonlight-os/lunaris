# Lunaris streaming core

Lunaris is Moonlight OS's shared C streaming protocol library. Selene and
Helios consume the same revision so feature negotiation, QUIC framing,
multi-display, USB, microphone, camera, and read-only disk extensions cannot
silently drift between client and host.

It remains compatible with the upstream Moonlight core protocol. Extensions
are negotiated explicitly and compatibility clients continue to work.

## Note to Developers

Lunaris requires its bundled ENet revision. It carries API/ABI changes for
IPv6 and retransmission reliability and must not be replaced by a system ENet.
