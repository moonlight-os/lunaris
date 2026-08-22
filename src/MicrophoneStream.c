#include "Limelight-internal.h"

#define MICROPHONE_PACKET_MAGIC 0x4D4C4D43u /* MLMC */
#define MICROPHONE_PACKET_VERSION 1
#define MICROPHONE_PACKET_HEADER_SIZE 36
#define MICROPHONE_MAX_OPUS_SIZE 1200
#define MICROPHONE_GCM_TAG_SIZE 16

static SOCKET microphoneSocket = INVALID_SOCKET;
static PPLT_CRYPTO_CONTEXT microphoneEncryptionCtx;
static uint64_t microphoneSequence;

static void putBe16(unsigned char* dst, uint16_t value) {
    dst[0] = (unsigned char)(value >> 8);
    dst[1] = (unsigned char)value;
}

static void putBe32(unsigned char* dst, uint32_t value) {
    dst[0] = (unsigned char)(value >> 24);
    dst[1] = (unsigned char)(value >> 16);
    dst[2] = (unsigned char)(value >> 8);
    dst[3] = (unsigned char)value;
}

static void putBe64(unsigned char* dst, uint64_t value) {
    putBe32(dst, (uint32_t)(value >> 32));
    putBe32(dst + 4, (uint32_t)value);
}

void initializeMicrophoneStream(void) {
    microphoneSequence = 0;
    microphoneEncryptionCtx = PltCreateCryptoContext();
}

void destroyMicrophoneStream(void) {
    if (microphoneSocket != INVALID_SOCKET) {
        closeSocket(microphoneSocket);
        microphoneSocket = INVALID_SOCKET;
    }
    if (microphoneEncryptionCtx != NULL) {
        PltDestroyCryptoContext(microphoneEncryptionCtx);
        microphoneEncryptionCtx = NULL;
    }
    microphoneSequence = 0;
}

int LiSendMicrophoneOpus(const void* opusData, uint16_t opusLength,
                         uint32_t timestamp, uint16_t samples, uint8_t channels) {
    unsigned char packet[MICROPHONE_PACKET_HEADER_SIZE + 8 + MICROPHONE_MAX_OPUS_SIZE];
    unsigned char plaintext[8 + MICROPHONE_MAX_OPUS_SIZE];
    unsigned char iv[12] = {0};
    LC_SOCKADDR destination;
    int encryptedLength;
    uint64_t sequence;

    if (opusData == NULL || opusLength == 0 || opusLength > MICROPHONE_MAX_OPUS_SIZE ||
        samples == 0 || (channels != 1 && channels != 2) ||
        MicrophonePortNumber == 0 || !(SunshineFeatureFlags & LI_FF_MICROPHONE_UPLINK) ||
        LiGetPeerFeatureVersion(ML_FEATURE_MICROPHONE) == 0 || microphoneEncryptionCtx == NULL) {
        return -1;
    }

    if (microphoneSocket == INVALID_SOCKET) {
        microphoneSocket = bindUdpSocket(RemoteAddr.ss_family, &LocalAddr, AddrLen, 0, SOCK_QOS_TYPE_AUDIO);
        if (microphoneSocket == INVALID_SOCKET) {
            return LastSocketFail();
        }
    }

    sequence = microphoneSequence++;
    if (microphoneSequence == 0) {
        /* Never reuse a GCM nonce within one session. */
        return -1;
    }

    putBe32(packet, MICROPHONE_PACKET_MAGIC);
    packet[4] = MICROPHONE_PACKET_VERSION;
    packet[5] = 0;
    putBe16(packet + 6, MICROPHONE_PACKET_HEADER_SIZE);
    putBe32(packet + 8, ControlConnectData);
    putBe64(packet + 12, sequence);

    putBe32(plaintext, timestamp);
    putBe16(plaintext + 4, samples);
    plaintext[6] = channels;
    plaintext[7] = 0;
    memcpy(plaintext + 8, opusData, opusLength);

    putBe64(iv, sequence);
    iv[10] = 'M';
    iv[11] = 'C';
    if (!PltEncryptMessage(microphoneEncryptionCtx, ALGORITHM_AES_GCM, 0,
                           (unsigned char*)StreamConfig.remoteInputAesKey,
                           sizeof(StreamConfig.remoteInputAesKey), iv, sizeof(iv),
                           packet + 20, MICROPHONE_GCM_TAG_SIZE,
                           plaintext, 8 + opusLength,
                           packet + MICROPHONE_PACKET_HEADER_SIZE, &encryptedLength)) {
        return -1;
    }

    putBe16(packet + 6, (uint16_t)(MICROPHONE_PACKET_HEADER_SIZE + encryptedLength));
    memcpy(&destination, &RemoteAddr, sizeof(destination));
    SET_PORT(&destination, MicrophonePortNumber);
    if (sendto(microphoneSocket, (char*)packet,
               MICROPHONE_PACKET_HEADER_SIZE + encryptedLength, 0,
               (struct sockaddr*)&destination, AddrLen) == SOCKET_ERROR) {
        return LastSocketFail();
    }
    return 0;
}
