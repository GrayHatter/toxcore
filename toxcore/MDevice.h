/** MDevice.h
 *
 * Multidevice interface for Toxcore
 *
 */

#ifndef MULTIDEV_H
#define MULTIDEV_H

#include "tox.h"
#include "Messenger.h"
#include "tox_connection.h"

/* TODO: These should only live in Messenger.h */
#define MAX_NAME_LENGTH 128
#define MAX_DEVICE_COUNT 16

#define MDEV_CALLBACK_INDEX 0

typedef enum {
    NO_MDEV,
    /* Device is blocked */
    MDEV_REMOVED,
    MDEV_REFUSED,
    MDEV_PENDING,
    /* Device is active */
    MDEV_OK,
    MDEV_CONFIRMED,
    MDEV_ONLINE,

} MDEV_STATUS;

typedef struct {
    MDEV_STATUS status; //0 no device, 1-3 device confimed, 4-5 device is blocked
    uint8_t     real_pk[crypto_box_PUBLICKEYBYTES];

    int         toxconn_id;

    uint64_t    last_seen_time;

    uint8_t     localname[MAX_NAME_LENGTH];
    uint16_t    localname_length;

    uint8_t     remotename[MAX_NAME_LENGTH];
    uint16_t    remotename_length;
} Device;

typedef struct Messenger Messenger;

typedef struct MDevice MDevice;

struct MDevice {
    Messenger       *m;

    Networking_Core *net;
    Net_Crypto *net_crypto;

    Onion *onion;
    Onion_Announce *onion_a;
    Onion_Client *onion_c;

    Tox_Connections *dev_conns;

    Device          *device;

    uint32_t        device_count;

    uint8_t status;

};

typedef struct Tox Tox;

/* TODO DOCUMENT THIS FXN */
void do_multidevice(MDevice *dev);


/* TODO DOCUMENT THIS FXN */
int mdev_add_new_device_self(MDevice *dev, const uint8_t *real_pk);

#endif
