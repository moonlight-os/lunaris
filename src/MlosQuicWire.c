#include "MlosQuicWire.h"

#include <string.h>

#define MLOS_QUIC_STREAM_MAGIC_0 'M'
#define MLOS_QUIC_STREAM_MAGIC_1 '7'
#define MLOS_QUIC_STREAM_MAGIC_2 'Q'
#define MLOS_QUIC_STREAM_MAGIC_3 'S'
#define MLOS_QUIC_DATAGRAM_MAGIC_0 'M'
#define MLOS_QUIC_DATAGRAM_MAGIC_1 '7'

static void put16(uint8_t* destination, uint16_t value) {
    destination[0] = (uint8_t)(value >> 8);
    destination[1] = (uint8_t)value;
}

static uint16_t get16(const uint8_t* source) {
    return (uint16_t)(((uint16_t)source[0] << 8) | source[1]);
}

static bool validStreamChannel(uint8_t channel) {
    return channel <= MLOS_QUIC_STREAM_SYSTEM_DISK;
}

static bool validDatagramChannel(uint8_t channel) {
    return channel >= MLOS_QUIC_DATAGRAM_VIDEO && channel <= MLOS_QUIC_DATAGRAM_CAMERA;
}

bool MlosQuicEncodeStreamPreface(uint8_t* destination, size_t destinationLength,
                                uint8_t channel, uint16_t flags) {
    if (destination == NULL || destinationLength != MLOS_QUIC_STREAM_PREFACE_SIZE ||
            !validStreamChannel(channel)) {
        return false;
    }

    destination[0] = MLOS_QUIC_STREAM_MAGIC_0;
    destination[1] = MLOS_QUIC_STREAM_MAGIC_1;
    destination[2] = MLOS_QUIC_STREAM_MAGIC_2;
    destination[3] = MLOS_QUIC_STREAM_MAGIC_3;
    destination[4] = MLOS_QUIC_WIRE_VERSION;
    destination[5] = channel;
    put16(destination + 6, flags);
    memset(destination + 8, 0, 4);
    return true;
}

bool MlosQuicDecodeStreamPreface(const uint8_t* source, size_t sourceLength,
                                MLOS_QUIC_STREAM_PREFACE* preface) {
    if (source == NULL || preface == NULL || sourceLength != MLOS_QUIC_STREAM_PREFACE_SIZE ||
            source[0] != MLOS_QUIC_STREAM_MAGIC_0 || source[1] != MLOS_QUIC_STREAM_MAGIC_1 ||
            source[2] != MLOS_QUIC_STREAM_MAGIC_2 || source[3] != MLOS_QUIC_STREAM_MAGIC_3 ||
            source[4] != MLOS_QUIC_WIRE_VERSION || !validStreamChannel(source[5]) ||
            source[8] != 0 || source[9] != 0 || source[10] != 0 || source[11] != 0) {
        return false;
    }

    MLOS_QUIC_STREAM_PREFACE parsed = {source[5], get16(source + 6)};
    *preface = parsed;
    return true;
}

bool MlosQuicEncodeDatagramHeader(uint8_t* destination, size_t destinationLength,
                                 uint8_t channel, uint16_t flags, uint16_t payloadLength) {
    if (destination == NULL || destinationLength != MLOS_QUIC_DATAGRAM_HEADER_SIZE ||
            !validDatagramChannel(channel) || payloadLength == 0) {
        return false;
    }

    destination[0] = MLOS_QUIC_DATAGRAM_MAGIC_0;
    destination[1] = MLOS_QUIC_DATAGRAM_MAGIC_1;
    destination[2] = MLOS_QUIC_WIRE_VERSION;
    destination[3] = channel;
    put16(destination + 4, flags);
    put16(destination + 6, payloadLength);
    return true;
}

bool MlosQuicDecodeDatagramHeader(const uint8_t* source, size_t sourceLength,
                                 MLOS_QUIC_DATAGRAM_HEADER* header) {
    if (source == NULL || header == NULL || sourceLength < MLOS_QUIC_DATAGRAM_HEADER_SIZE ||
            source[0] != MLOS_QUIC_DATAGRAM_MAGIC_0 || source[1] != MLOS_QUIC_DATAGRAM_MAGIC_1 ||
            source[2] != MLOS_QUIC_WIRE_VERSION || !validDatagramChannel(source[3])) {
        return false;
    }

    MLOS_QUIC_DATAGRAM_HEADER parsed = {source[3], get16(source + 4), get16(source + 6)};
    if (parsed.payloadLength == 0 ||
            (size_t)parsed.payloadLength != sourceLength - MLOS_QUIC_DATAGRAM_HEADER_SIZE) {
        return false;
    }
    *header = parsed;
    return true;
}

bool MlosQuicEncodeAuth(uint8_t* destination, size_t destinationLength,
                       const uint8_t token[MLOS_QUIC_TOKEN_SIZE],
                       const uint8_t certificateHash[MLOS_QUIC_CERT_HASH_SIZE]) {
    if (destination == NULL || destinationLength != MLOS_QUIC_AUTH_SIZE ||
            token == NULL || certificateHash == NULL) {
        return false;
    }
    destination[0] = MLOS_QUIC_WIRE_VERSION;
    destination[1] = destination[2] = destination[3] = 0;
    memcpy(destination + 4, token, MLOS_QUIC_TOKEN_SIZE);
    memcpy(destination + 4 + MLOS_QUIC_TOKEN_SIZE, certificateHash, MLOS_QUIC_CERT_HASH_SIZE);
    return true;
}

bool MlosQuicDecodeAuth(const uint8_t* source, size_t sourceLength, MLOS_QUIC_AUTH* auth) {
    if (source == NULL || auth == NULL || sourceLength != MLOS_QUIC_AUTH_SIZE ||
            source[0] != MLOS_QUIC_WIRE_VERSION || source[1] != 0 || source[2] != 0 || source[3] != 0) {
        return false;
    }
    MLOS_QUIC_AUTH parsed;
    memcpy(parsed.token, source + 4, MLOS_QUIC_TOKEN_SIZE);
    memcpy(parsed.clientCertificateSha256, source + 4 + MLOS_QUIC_TOKEN_SIZE,
           MLOS_QUIC_CERT_HASH_SIZE);
    *auth = parsed;
    return true;
}
