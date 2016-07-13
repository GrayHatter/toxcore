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

    MDEV_SYNC_SELF,             /* TODO SYNC_SELF not yet implemented */
    MDEV_SYNC_SELF_NAME,
    MDEV_SYNC_SELF_STATUS_MSG,
    MDEV_SYNC_SELF_STATE,
    MDEV_SYNC_SELF_DONE,

    MDEV_SYNC_CONTACT_START,
    MDEV_SYNC_CONTACT_COUNT,
    MDEV_SYNC_CONTACT_APPEND,         /* First PubKey for this friend                   */
    MDEV_SYNC_CONTACT_APPEND_DEVICE,  /* Other known devices for the last sent friend   */
    MDEV_SYNC_CONTACT_REMOVE,
    MDEV_SYNC_CONTACT_REJECT,
    MDEV_SYNC_CONTACT_DONE,
    MDEV_SYNC_CONTACT_COMMIT,
    MDEV_SYNC_CONTACT_ERROR,

    MDEV_SYNC_DEVICE,           /* TODO SYNC_DEVICE not yet implemented */
    MDEV_SYNC_DEVICE_COUNT,
    MDEV_SYNC_DEVICE_APPEND,
    MDEV_SYNC_DEVICE_REMOVE,
    MDEV_SYNC_DEVICE_REJECT,
    MDEV_SYNC_DEVICE_DONE,
    MDEV_SYNC_DEVICE_ERROR,

    MDEV_SYNC_MESSAGES,         /* TODO help */

    MDEV_SYNC_NOTHING,


    /* Send type packets are for active changes that were just made by a client. */


    MDEV_SEND_SELF_NAME,
    MDEV_SEND_SELF_STATUS_MSG, /* User flavor text */
    MDEV_SEND_SELF_STATE,      /* User state (e.g. Available, Away, DND */

    MDEV_SEND_CONTACT_ADDED,    /* TODO */
    MDEV_SEND_CONTACT_ACCEPTED, /* TODO */
    MDEV_SEND_CONTACT_REMOVED,  /* TODO */

    MDEV_SEND_DEVICE_ADDED,     /* TODO */
    MDEV_SEND_DEVICE_ACCEPTED,  /* TODO */
    MDEV_SEND_DEVICE_REMOVED,   /* TODO */

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


/* TODO: write a callback to notify the client if there was an error
 * during sync */
typedef enum {
    MDEV_SYNC_ERR_NONE,
    MDEV_SYNC_ERR_REFUSED,
    MDEV_SYNC_ERR_UNSUPPORTED,

    MDEV_SYNC_ERR_UNEXPECTED, /* Used if one device tries to sync out of order */
    MDEV_SYNC_ERR_VERSION_INCOPAT, /* MDevice version mismatch; can not sync */
    MDEV_SYNC_ERR_UNKNOWN,

} MDEV_SYNC_ERR;

typedef enum {
    MDEV_INTERN_SYNC_ERR_NONE,

    MDEV_INTERN_SYNC_ERR_CALLBACK_NOT_SET,

} MDEV_INTERN_SYNC_ERR;

/* The status of a public-key as returned by mdev_find_pubkey */
typedef enum {
    MDEV_PUBKEY_STATUS_NOTFOUND         = +0,
    MDEV_PUBKEY_STATUS_OURSELF          = -1,
    MDEV_PUBKEY_STATUS_OUR_DEVICE       = -2,
    MDEV_PUBKEY_STATUS_OUR_DHT          = -3,
    MDEV_PUBKEY_STATUS_FRIEND           = -4,
    MDEV_PUBKEY_STATUS_FRIENDS_DEVICE   = -5,
    MDEV_PUBKEY_STATUS_IN_SYNCLIST      = -6,
} MDEV_PUBKEY_STATUS;

typedef struct {
    MDEV_STATUS status;

    uint8_t     real_pk[crypto_box_PUBLICKEYBYTES];
    int         toxconn_id;
    uint64_t    last_seen_time;

    uint8_t     name[MAX_NAME_LENGTH];
    uint16_t    name_length;

    /* Sync status */
    MDEV_SYNC_ROLE      sync_role;
    MDEV_SYNC_STATUS    sync_status;

    Friend      *sync_friendlist;
    uint32_t    sync_friendlist_capacity;
    uint32_t    sync_friendlist_size;
} Device;

struct MDevice {
    Tox* tox;

    Device          *devices;
    uint32_t        devices_count;

    uint8_t         (*removed_devices)[crypto_box_PUBLICKEYBYTES];
    uint32_t        removed_devices_count;


    /* Callbacks */
    tox_mdev_self_name_cb (*self_name_change);
    void *self_name_change_userdata;
    tox_mdev_self_status_message_cb (*self_status_message_change);
    void *self_status_message_change_userdata;
    tox_mdev_self_state_cb (*self_user_state_change);
    void *self_user_state_change_userdata;

    tox_mdev_sent_message_cb (*mdev_sent_message);
    void *mdev_sent_message_userdata;

    MDevice_Options options;
};

typedef struct Tox Tox;

/**
 * Does house keeping for multidevice
 *
 * @param tox the current tox instance
 */
void do_multidevice(Tox *tox);

/**
 * Creates a new MDevice instance
 * Should only be called by tox_new()
 * @param  tox the current tox instance
 * @param  options the options that should be set
 * @param  error   buffer used for setting the error
 * @return         on success returns the newly created MDevice instance
 * @return         on failure returns NULL
 */
MDevice *new_mdevice(Tox* tox, MDevice_Options *options, unsigned int *error);

/**
 * Adds a new device to the device list
 *
 * @param  tox     The current tox instance
 * @param  name    The devices name
 * @param  length  Length of the devices name
 * @param  real_pk The devices public key
 * @return         number of devices added on success
 * @return         -2 if real_pk is invalid
 * @return         -3 if real_pk equals
 * @return         -4 if the device id is blacklisted
 * @return         -5 if the device id already exists
 */
int mdev_add_new_device_self(Tox *tox, const uint8_t* name, size_t length, const uint8_t *real_pk);


/**
 * Removes a device and adds it to the removed_devices blacklist
 *
 * @param  tox     The current tox instance
 * @param  address The device's public key
 * @return         0 on success
 * @return         -1 if the device id could not be found
 */
int mdev_remove_device(Tox* tox, const uint8_t *address);

/**
 * Returns the number of devices in your device list
 *
 * @param  tox The current tox instance
 * @return     Returns the number of devices in the device list.
 */
int32_t mdev_get_dev_count(Tox *tox);

/**
 * If devices exists, pk is set the the real_pk at that device index
 *
 * @param  tox    The current tox instance
 * @param  number The device number
 * @param  pk     The devices public key must be at least crypto_box_PUBLICKEYBYTES
 * @return        1 on success, 0 on failure
 */
bool mdev_get_dev_pubkey(Tox *tox, uint32_t number, uint8_t pk[crypto_box_PUBLICKEYBYTES]);

/* Multi-device set callbacks */

/**
 * Sets the callback for receiving name changes from remote devices. Pass NULL for function to unset.
 *
 * @param tox      The current tox instance
 * @param function The function that will be called
 * @param userdata The data that will be passed to the function
 */
void mdev_callback_self_name(Tox *tox, tox_mdev_self_name_cb *function, void *userdata);

/**
 * Sets the callback for receiving status changes from remote devices. Pass NULL for furnciton to unset.
 *
 * @param tox      The current tox instance
 * @param function The function that will be called
 * @param userdata The data that will be passed to the function
 */
void mdev_callback_self_status_message(Tox *tox, tox_mdev_self_status_message_cb *function, void *userdata);

/**
 * Sets the callback for receiving state changes from remote devices. Pass NULL for function to unset.
 *
 * @param tox      The current tox instance
 * @param function The function that will be called
 * @param userdata The data that will be passed to the function
 */
void mdev_callback_self_state(Tox *tox, tox_mdev_self_state_cb *function, void *userdata);

/**
 * Sets the callback for sent messages
 *
 * @param tox      The current tox instance
 * @param fxn      The function that will be called
 * @param userdata The data that will be passed to the function
 */
void mdev_callback_mdev_sent_message(Tox *tox, tox_mdev_sent_message_cb *fxn, void *userdata);


/* Multi-device send data fxns */

/**
 * Sends name changes to your other devices
 * called by tox_self_set_name()
 * @param tox    The current tox instance
 * @param name   The users new name
 * @param length Length of name
 * @return       1 on success, 0 on failure
 */
bool mdev_send_name_change(Tox *tox, const uint8_t *name, size_t length);

/**
 * Sends status changes to your other devices
 * Called by tox_self_set_status_message()
 * @param  tox    The current tox instance
 * @param  status The users new status
 * @param  length Length of status
 * @return        1 on success, 0 on failure
 */
bool mdev_send_status_message_change(Tox *tox, const uint8_t *status, size_t length);

/**
 * Sends state changes to your other devices
 *
 * @param  tox   The current tox instance
 * @param  state The state the user should be in
 * @return       1 on success, 0 on failure
 */
bool mdev_send_state_change(Tox *tox, const TOX_USER_STATUS state);

/**
 * Sends a message to the specified friend
 *
 * @param  tox           The current tox instance
 * @param  friend_number The friend you want to send the message to
 * @param  type          The type of message that is being sent
 * @param  message       The message that is going to be sent
 * @param  length        Length of the message
 * @return               0 on success
 * @return               -2 if the message is longer than MAX_CRYPTO_DATA_SIZE
 */
int  mdev_send_message_generic(Tox* tox, uint32_t friend_number, TOX_MESSAGE_TYPE type,
                               const uint8_t *message, size_t length);

/**
 * Calculates the size of the MDevice structure
 * Designed to be used by the save function
 * @param  tox The current tox instance
 * @return     Size of the MDevice struct
 */
size_t mdev_size(const Tox *tox);

/**
 * Generates the MDevice data that should be saved
 *
 * @param  tox  The current tox instance
 * @param  data The buffer the save data is written to
 * @return      data
 */
uint8_t *mdev_save(const Tox *tox, uint8_t *data);

/**
 * Loads the MDevice data from the sections of the saved state
 *
 * @param  tox    The current tox instance
 * @param  data   The data that is going to be loaded
 * @param  length Length of data
 * @param  type   Type of save
 * @return        0 on success
 * @return        -1 if length is less than sizeof(uint8_t)
 */
int mdev_save_read_sections_callback(Tox *tox, const uint8_t *data, uint32_t length, uint16_t type);

#endif
