#include "Limelight-internal.h"

#define CAMERA_PACKET_MAGIC 0x4D4C4341u /* MLCA */
#define CAMERA_PACKET_VERSION 1
#define CAMERA_PACKET_HEADER_SIZE 36
#define CAMERA_FRAGMENT_HEADER_SIZE 26
#define CAMERA_FRAGMENT_DATA_SIZE 1050
#define CAMERA_MAX_FRAME_SIZE (4u * 1024u * 1024u)
#define CAMERA_GCM_TAG_SIZE 16
#define CAMERA_FORMAT_MJPEG 1

static SOCKET cameraSocket = INVALID_SOCKET;
static PPLT_CRYPTO_CONTEXT cameraEncryptionCtx;
static uint64_t cameraSequence;

static void putBe16Camera(unsigned char* dst, uint16_t value) {
    dst[0] = (unsigned char)(value >> 8);
    dst[1] = (unsigned char)value;
}

static void putBe32Camera(unsigned char* dst, uint32_t value) {
    dst[0] = (unsigned char)(value >> 24);
    dst[1] = (unsigned char)(value >> 16);
    dst[2] = (unsigned char)(value >> 8);
    dst[3] = (unsigned char)value;
}

static void putBe64Camera(unsigned char* dst, uint64_t value) {
    putBe32Camera(dst, (uint32_t)(value >> 32));
    putBe32Camera(dst + 4, (uint32_t)value);
}

void initializeCameraStream(void) {
    cameraSequence = 0;
    cameraEncryptionCtx = PltCreateCryptoContext();
}

void destroyCameraStream(void) {
    if (cameraSocket != INVALID_SOCKET) {
        closeSocket(cameraSocket);
        cameraSocket = INVALID_SOCKET;
    }
    if (cameraEncryptionCtx != NULL) {
        PltDestroyCryptoContext(cameraEncryptionCtx);
        cameraEncryptionCtx = NULL;
    }
    cameraSequence = 0;
}

int LiSendCameraMjpeg(const void* jpegData, uint32_t jpegLength,
                      uint32_t frameId, uint32_t timestampMs,
                      uint16_t width, uint16_t height) {
    unsigned char* packet;
    unsigned char* plaintext;
    unsigned char iv[12] = {0};
    LC_SOCKADDR destination;
    uint32_t offset = 0;
    uint16_t fragmentCount;
    int result = 0;

    if (jpegData == NULL || jpegLength == 0 || jpegLength > CAMERA_MAX_FRAME_SIZE ||
        width == 0 || height == 0 || CameraPortNumber == 0 ||
        !(SunshineFeatureFlags & LI_FF_CAMERA_UPLINK) ||
        LiGetPeerFeatureVersion(ML_FEATURE_CAMERA) == 0 || cameraEncryptionCtx == NULL) {
        return -1;
    }

    fragmentCount = (uint16_t)((jpegLength + CAMERA_FRAGMENT_DATA_SIZE - 1) /
                               CAMERA_FRAGMENT_DATA_SIZE);
    if (fragmentCount == 0) {
        return -1;
    }

    if (cameraSocket == INVALID_SOCKET) {
        cameraSocket = bindUdpSocket(RemoteAddr.ss_family, &LocalAddr, AddrLen, 0,
                                     SOCK_QOS_TYPE_VIDEO);
        if (cameraSocket == INVALID_SOCKET) {
            return LastSocketFail();
        }
    }

    packet = (unsigned char*)malloc(CAMERA_PACKET_HEADER_SIZE +
                                    CAMERA_FRAGMENT_HEADER_SIZE + CAMERA_FRAGMENT_DATA_SIZE);
    plaintext = (unsigned char*)malloc(CAMERA_FRAGMENT_HEADER_SIZE + CAMERA_FRAGMENT_DATA_SIZE);
    if (packet == NULL || plaintext == NULL) {
        free(packet);
        free(plaintext);
        return -1;
    }

    memcpy(&destination, &RemoteAddr, sizeof(destination));
    SET_PORT(&destination, CameraPortNumber);

    for (uint16_t fragmentIndex = 0; fragmentIndex < fragmentCount; ++fragmentIndex) {
        uint32_t remaining = jpegLength - offset;
        uint16_t fragmentLength = (uint16_t)(remaining > CAMERA_FRAGMENT_DATA_SIZE ?
                                             CAMERA_FRAGMENT_DATA_SIZE : remaining);
        uint64_t sequence = cameraSequence++;
        int encryptedLength;
        int packetLength;

        if (cameraSequence == 0) {
            result = -1;
            break;
        }

        putBe32Camera(packet, CAMERA_PACKET_MAGIC);
        packet[4] = CAMERA_PACKET_VERSION;
        packet[5] = 0;
        putBe16Camera(packet + 6, 0);
        putBe32Camera(packet + 8, ControlConnectData);
        putBe64Camera(packet + 12, sequence);

        putBe32Camera(plaintext, frameId);
        putBe32Camera(plaintext + 4, timestampMs);
        putBe16Camera(plaintext + 8, width);
        putBe16Camera(plaintext + 10, height);
        plaintext[12] = CAMERA_FORMAT_MJPEG;
        plaintext[13] = 0;
        putBe16Camera(plaintext + 14, fragmentIndex);
        putBe16Camera(plaintext + 16, fragmentCount);
        putBe32Camera(plaintext + 18, jpegLength);
        putBe32Camera(plaintext + 22, offset);
        memcpy(plaintext + CAMERA_FRAGMENT_HEADER_SIZE,
               (const unsigned char*)jpegData + offset, fragmentLength);

        memset(iv, 0, sizeof(iv));
        putBe64Camera(iv, sequence);
        iv[10] = 'C';
        iv[11] = 'A';
        if (!PltEncryptMessage(cameraEncryptionCtx, ALGORITHM_AES_GCM, 0,
                               (unsigned char*)StreamConfig.remoteInputAesKey,
                               sizeof(StreamConfig.remoteInputAesKey), iv, sizeof(iv),
                               packet + 20, CAMERA_GCM_TAG_SIZE,
                               plaintext, CAMERA_FRAGMENT_HEADER_SIZE + fragmentLength,
                               packet + CAMERA_PACKET_HEADER_SIZE, &encryptedLength)) {
            result = -1;
            break;
        }

        packetLength = CAMERA_PACKET_HEADER_SIZE + encryptedLength;
        putBe16Camera(packet + 6, (uint16_t)packetLength);
        if (sendto(cameraSocket, (char*)packet, packetLength, 0,
                   (struct sockaddr*)&destination, AddrLen) == SOCKET_ERROR) {
            result = LastSocketFail();
            break;
        }
        offset += fragmentLength;
    }

    free(plaintext);
    free(packet);
    return result;
}
