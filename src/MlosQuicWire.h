#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MLOS_QUIC_ALPN "moonlight-os/1"
#define MLOS_QUIC_WIRE_VERSION 1
#define MLOS_QUIC_TOKEN_SIZE 32
#define MLOS_QUIC_CERT_HASH_SIZE 32
#define MLOS_QUIC_STREAM_PREFACE_SIZE 12
#define MLOS_QUIC_DATAGRAM_HEADER_SIZE 8
#define MLOS_QUIC_AUTH_SIZE (4 + MLOS_QUIC_TOKEN_SIZE + MLOS_QUIC_CERT_HASH_SIZE)

typedef enum _MLOS_QUIC_STREAM_CHANNEL {
    MLOS_QUIC_STREAM_AUTH = 0,
    MLOS_QUIC_STREAM_RTSP = 1,
    MLOS_QUIC_STREAM_CONTROL = 2,
    MLOS_QUIC_STREAM_INPUT = 3,
    MLOS_QUIC_STREAM_USB = 4,
    MLOS_QUIC_STREAM_MICROPHONE = 5,
    MLOS_QUIC_STREAM_CAMERA = 6,
    MLOS_QUIC_STREAM_SYSTEM_DISK = 7,
} MLOS_QUIC_STREAM_CHANNEL;

typedef enum _MLOS_QUIC_DATAGRAM_CHANNEL {
    MLOS_QUIC_DATAGRAM_VIDEO = 1,
    MLOS_QUIC_DATAGRAM_AUDIO = 2,
    MLOS_QUIC_DATAGRAM_CONTROL = 3,
    MLOS_QUIC_DATAGRAM_INPUT = 4,
    MLOS_QUIC_DATAGRAM_MICROPHONE = 5,
    MLOS_QUIC_DATAGRAM_CAMERA = 6,
} MLOS_QUIC_DATAGRAM_CHANNEL;

typedef struct _MLOS_QUIC_STREAM_PREFACE {
    uint8_t channel;
    uint16_t flags;
} MLOS_QUIC_STREAM_PREFACE;

typedef struct _MLOS_QUIC_DATAGRAM_HEADER {
    uint8_t channel;
    uint16_t flags;
    uint16_t payloadLength;
} MLOS_QUIC_DATAGRAM_HEADER;

typedef struct _MLOS_QUIC_AUTH {
    uint8_t token[MLOS_QUIC_TOKEN_SIZE];
    uint8_t clientCertificateSha256[MLOS_QUIC_CERT_HASH_SIZE];
} MLOS_QUIC_AUTH;

bool MlosQuicEncodeStreamPreface(uint8_t* destination, size_t destinationLength,
                                uint8_t channel, uint16_t flags);
bool MlosQuicDecodeStreamPreface(const uint8_t* source, size_t sourceLength,
                                MLOS_QUIC_STREAM_PREFACE* preface);
bool MlosQuicEncodeDatagramHeader(uint8_t* destination, size_t destinationLength,
                                 uint8_t channel, uint16_t flags, uint16_t payloadLength);
bool MlosQuicDecodeDatagramHeader(const uint8_t* source, size_t sourceLength,
                                 MLOS_QUIC_DATAGRAM_HEADER* header);
bool MlosQuicEncodeAuth(uint8_t* destination, size_t destinationLength,
                       const uint8_t token[MLOS_QUIC_TOKEN_SIZE],
                       const uint8_t certificateHash[MLOS_QUIC_CERT_HASH_SIZE]);
bool MlosQuicDecodeAuth(const uint8_t* source, size_t sourceLength, MLOS_QUIC_AUTH* auth);

#ifdef __cplusplus
}
#endif
