#include "MlosQuicWire.h"

#include <assert.h>
#include <string.h>

int main(void) {
    uint8_t bytes[MLOS_QUIC_AUTH_SIZE] = {0};
    uint8_t token[MLOS_QUIC_TOKEN_SIZE];
    uint8_t certificate[MLOS_QUIC_CERT_HASH_SIZE];
    memset(token, 0x2a, sizeof(token));
    memset(certificate, 0x5c, sizeof(certificate));

    assert(MlosQuicEncodeStreamPreface(bytes, MLOS_QUIC_STREAM_PREFACE_SIZE,
                                      MLOS_QUIC_STREAM_RTSP, 0));
    MLOS_QUIC_STREAM_PREFACE preface;
    assert(MlosQuicDecodeStreamPreface(bytes, MLOS_QUIC_STREAM_PREFACE_SIZE, &preface));
    assert(preface.channel == MLOS_QUIC_STREAM_RTSP && preface.flags == 0);
    bytes[11] = 1;
    assert(!MlosQuicDecodeStreamPreface(bytes, MLOS_QUIC_STREAM_PREFACE_SIZE, &preface));

    memset(bytes, 0, sizeof(bytes));
    assert(MlosQuicEncodeDatagramHeader(bytes, MLOS_QUIC_DATAGRAM_HEADER_SIZE,
                                       MLOS_QUIC_DATAGRAM_VIDEO, 0, 3));
    bytes[8] = 1; bytes[9] = 2; bytes[10] = 3;
    MLOS_QUIC_DATAGRAM_HEADER datagram;
    assert(MlosQuicDecodeDatagramHeader(bytes, 11, &datagram));
    assert(datagram.channel == MLOS_QUIC_DATAGRAM_VIDEO && datagram.payloadLength == 3);
    assert(!MlosQuicDecodeDatagramHeader(bytes, 10, &datagram));

    assert(MlosQuicEncodeAuth(bytes, sizeof(bytes), token, certificate));
    MLOS_QUIC_AUTH auth;
    assert(MlosQuicDecodeAuth(bytes, sizeof(bytes), &auth));
    assert(memcmp(auth.token, token, sizeof(token)) == 0);
    assert(memcmp(auth.clientCertificateSha256, certificate, sizeof(certificate)) == 0);
    bytes[1] = 1;
    assert(!MlosQuicDecodeAuth(bytes, sizeof(bytes), &auth));
    return 0;
}
