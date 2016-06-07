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

/**
 * The major version number. Incremented when the API or ABI changes in an
 * incompatible way.
 */
#define TOXMD_VERSION_MAJOR               0u

/**
 * The minor version number. Incremented when functionality is added without
 * breaking the API or ABI. Set to 0 when the major version number is
 * incremented.
 */
#define TOXMD_VERSION_MINOR               0u

/**
 * The patch or revision number. Incremented when bugfixes are applied without
 * changing any functionality or API or ABI.
 */
#define TOXMD_VERSION_PATCH               0u

/**
 * A macro to check at preprocessing time whether the client code is compatible
 * with the installed version of Tox.
 */
#define TOXMD_VERSION_IS_API_COMPATIBLE(MAJOR, MINOR, PATCH)      \
  (TOXMD_VERSION_MAJOR == MAJOR &&                                \
   (TOXMD_VERSION_MINOR > MINOR ||                                \
    (TOXMD_VERSION_MINOR == MINOR &&                              \
     TOXMD_VERSION_PATCH >= PATCH)))

/**
 * A macro to make compilation fail if the client code is not compatible with
 * the installed version of Tox.
 */
#define TOXMD_VERSION_REQUIRE(MAJOR, MINOR, PATCH)                \
  typedef char tox_required_version[TOX_IS_COMPATIBLE(MAJOR, MINOR, PATCH) ? 1 : -1]

/**
 * Return the major version number of the library. Can be used to display the
 * Tox library version or to check whether the client is compatible with the
 * dynamically linked version of Tox.
 */
uint32_t toxmd_version_major(void);

/**
 * Return the minor version number of the library.
 */
uint32_t toxmd_version_minor(void);

/**
 * Return the patch number of the library.
 */
uint32_t toxmd_version_patch(void);

/**
 * Return whether the compiled library version is compatible with the passed
 * version numbers.
 */
bool toxmd_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch);

/**
 * A convenience macro to call toxmd_version_is_compatible with the currently
 * compiling API version.
 */
#define TOXMD_VERSION_IS_ABI_COMPATIBLE()                         \
  toxmd_version_is_compatible(TOXMD_VERSION_MAJOR, TOXMD_VERSION_MINOR, TOXMD_VERSION_PATCH)


/* TODO: These should only live in Messenger.h */
#define MAX_NAME_LENGTH 128

#define MDEV_CALLBACK_INDEX 0

typedef enum {
    MDEV_NULL_PKT,

    /* Sync type packets are for historical changes */
    MDEV_SYNC_META,
    MDEV_SYNC_META_UPTIME,

    MDEV_SYNC_SELF,
    MDEV_SYNC_SELF_NAME,
    MDEV_SYNC_SELF_MSG,
    MDEV_SYNC_SELF_STATUS,
    MDEV_SYNC_SELF_DONE,

    MDEV_SYNC_CONTACT_START,
    MDEV_SYNC_CONTACT_COUNT,
    MDEV_SYNC_CONTACT_APPEND,         /* First PubKey for this friend                   */
    MDEV_SYNC_CONTACT_APPEND_DEVICE,  /* Other known devices for the last sent friend   */
    MDEV_SYNC_CONTACT_REMOVE,
    MDEV_SYNC_CONTACT_REJECT,
    MDEV_SYNC_CONTACT_DONE,
    MDEV_SYNC_CONTACT_ERROR,

    MDEV_SYNC_DEVICE,
    MDEV_SYNC_DEVICE_COUNT,
    MDEV_SYNC_DEVICE_APPEND,
    MDEV_SYNC_DEVICE_REMOVE,
    MDEV_SYNC_DEVICE_REJECT,
    MDEV_SYNC_DEVICE_DONE,
    MDEV_SYNC_DEVICE_ERROR,

    MDEV_SYNC_MESSAGES,

    MDEV_SYNC_NOTHING,

    /* Send type packets are for active changes */
    MDEV_SEND_NAME,
    MDEV_SEND_MSG,
    MDEV_SEND_STATUS,
    MDEV_SEND_MESSAGE,
    MDEV_SEND_MESSAGE_ACTION,

} MDEV_PACKET_TYPE;

typedef enum {
    MDEV_PENDING,
    MDEV_CONFIRMED,
    MDEV_ONLINE,

} MDEV_STATUS;

typedef struct MDevice_Options {
    bool        enable_high_security; /* TODO Unsupported feature */

    bool        send_messages;

} MDevice_Options;

typedef struct {
    MDEV_STATUS status;
    uint8_t     real_pk[crypto_box_PUBLICKEYBYTES];

    int         toxconn_id;

    uint64_t    last_seen_time;

    uint8_t     name[MAX_NAME_LENGTH];
    uint16_t    name_length;
} Device;

typedef struct Messenger Messenger;
typedef struct MDevice MDevice;

/*
 * Role and status are used to determine where in the sync status we are.
 *     * The PRIMARY role will signal it's ready to start
 *     * Wait for the request sync request
 *     * Send all available data, followed by a DONE packet
 * The PRIMARY will then wait for the SECONDARY to either send back it's own
 * data, or send it's own DONE packet.
 *
 * Once the PRIMARY receives the DONE packet from the SECONDARY, it'll
 * signal it's ready to send the next section, then wait again for the request.
 */

typedef enum {
    MDEV_SYNC_ROLE_NONE,
    MDEV_SYNC_ROLE_PRIMARY,
    MDEV_SYNC_ROLE_SECONDARY,
} MDEV_SYNC_ROLE;

typedef enum {
    MDEV_SYNC_STATUS_NONE,
    MDEV_SYNC_STATUS_ACTIVE,


    MDEV_SYNC_STATUS_META_SENDING,
    MDEV_SYNC_STATUS_META_RECIVING,

    MDEV_SYNC_STATUS_FRIENDS_SENDING,
    MDEV_SYNC_STATUS_FRIENDS_RECIVING,

    MDEV_SYNC_STATUS_DEVICES_SENDING,
    MDEV_SYNC_STATUS_DEVICES_RECIVING,


    MDEV_SYNC_STATUS_DONE,
} MDEV_SYNC_STATUS;

struct MDevice {
    Tox* tox;

    Tox_Connections *dev_conns;

    Device          *devices;
    uint32_t        devices_count;

    uint8_t         (*removed_devices)[crypto_box_PUBLICKEYBYTES];
    uint32_t        removed_devices_count;

    /* Sync status */
    MDEV_SYNC_ROLE      sync_role;
    MDEV_SYNC_STATUS    sync_status;

    bool sync_active_friends;


    /* Callbacks */
    void (*self_name_change)(Tox *tox, uint32_t, const uint8_t *, size_t, void *);
    void *self_name_change_userdata;
    void (*self_status_message_change)(Tox *tox, uint32_t, const uint8_t *, size_t, void *);
    void *self_status_message_change_userdata;

    MDevice_Options options;
};

typedef struct Tox Tox;

/* TODO DOCUMENT THIS FXN */
void do_multidevice(MDevice *dev);

/* TODO DOCUMENT THIS FXN */
MDevice *new_mdevice(Tox* tox, Messenger_Options *options, unsigned int *error);

/* TODO DOCUMENT THIS FXN */
int mdev_add_new_device_self(Tox *tox, const uint8_t* name, size_t length, const uint8_t *real_pk);

/* Removes a device and adds it to the removed_devices blacklist */
int mdev_remove_device(Tox* tox, const uint8_t *address);

/* Multi-device set callbacks */
void mdev_callback_self_name_change(Tox *tox,
                                   void (*function)(Tox *tox, uint32_t, const uint8_t *, size_t, void *),
                                   void *userdata);
void mdev_callback_self_status_message_change(Tox *tox,
                                   void (*function)(Tox *tox, uint32_t, const uint8_t *, size_t, void *),
                                   void *userdata);

/* Multi-device send data fxns */
bool mdev_sync_name_change(Tox *tox, const uint8_t *name, size_t length);
bool mdev_sync_status_message_change(Tox *tox, const uint8_t *status, size_t length);
void mdev_send_message_generic(Tox* tox, uint32_t friend_number, TOX_MESSAGE_TYPE type,
                               const uint8_t *message, size_t length);

/* Return size of the mdev data (for saving) */
size_t mdev_size(const Tox *tox);

/* Save the mdev in data of size mdev_size(). */
uint8_t *mdev_save(const Tox *tox, uint8_t *data);

/* Loads the MDevice data from the sections of the saved state */
int mdev_save_read_sections_callback(Tox *tox, const uint8_t *data, uint32_t length, uint16_t type);

#endif
