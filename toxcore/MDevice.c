/** MDevice.c
 *
 * Multidevice interface for Toxcore
 *
 */

#include "MDevice.h"
#include "util.h"
#include "save.h"
#include "assert.h"
#include <limits.h>

#define SET_ERROR_PARAMETER(param, x) {if(param) {*param = x;}}

/******************************************************************************
 ******** Multi Device Version Helpers                                 ********
 ******************************************************************************/
uint32_t toxmd_version_major(void)
{
    return TOXMD_VERSION_MAJOR;
}

uint32_t toxmd_version_minor(void)
{
    return TOXMD_VERSION_MINOR;
}

uint32_t toxmd_version_patch(void)
{
    return TOXMD_VERSION_PATCH;
}

bool toxmd_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch)
{
  return (TOXMD_VERSION_MAJOR == major && /* Force the major version */
            (TOXMD_VERSION_MINOR > minor || /* Current minor version must be newer than requested -- or -- */
                (TOXMD_VERSION_MINOR == minor && TOXMD_VERSION_PATCH >= patch) /* the patch must be the same or newer */
            )
         );
}


/******************************************************************************
 ******** Multi-device internal helpers                                ********
 ******************************************************************************/
static int get_device_id(MDevice *dev, const uint8_t *real_pk);

static uint32_t get_device_count(const MDevice *dev)
{
    uint32_t i, count = 0;
    for (i = 0; i < dev->devices_count; ++i) {
        if (dev->devices[i].status) {
            ++count;
        }
    }
    return count;
}

static int realloc_mdev_list(MDevice *dev, uint32_t num)
{
    if (num == 0) {
        free(dev->devices);
        dev->devices = NULL;
        return 0;
    }

    Device *new_dev_list = realloc(dev->devices, num * sizeof(Device));

    if (new_dev_list == NULL)
        return -1;

    dev->devices = new_dev_list;
    return 0;
}

static int realloc_friend_dev_list(MDevice *mdev, uint32_t dev_num, uint32_t fr_num, uint32_t num)
{
    if (num == 0) {
        free(mdev->devices[dev_num].sync_friendlist[fr_num].dev_list);
        mdev->devices[dev_num].sync_friendlist[fr_num].dev_list = NULL;
        return 0;
    }

    F_Device *newlist = realloc(mdev->devices[dev_num].sync_friendlist[fr_num].dev_list, num * sizeof(F_Device));

    if (newlist == NULL) {
        return -1;
    }

    mdev->devices[dev_num].sync_friendlist[fr_num].dev_list = newlist;
    return 0;
}

static int realloc_mdev_removed_list(MDevice *dev, uint32_t num)
{
    if (num == 0) {
        free(dev->removed_devices);
        dev->removed_devices = NULL;
        return 0;
    }

    uint8_t (*removed_devices)[] = realloc(dev->removed_devices, num * crypto_box_PUBLICKEYBYTES);

    if (removed_devices == NULL)
        return -1;

    dev->removed_devices = removed_devices;
    return 0;
}

static uint8_t mdev_device_not_valid(const MDevice *dev, uint32_t dev_num)
{
    if (dev_num < dev->devices_count) {
        if (dev->devices[dev_num].status > MDEV_PENDING) {
            return 0;
        }
    }

    return 1;
}

static bool get_next_device_online(const MDevice *mdev, uint32_t *device)
{
    if (!device) {
        return 0;
    }

    uint32_t i;
    for (i = (*device); ++i < mdev->devices_count; ) {
        if (mdev->devices[i].status == MDEV_ONLINE) {
            *device = i;
            return 1;
        }
    }
    return 0;
}

static bool get_next_device_synced(const MDevice *mdev, uint32_t *device)
{
    if (!device) {
        return 0;
    }

    uint32_t i;
    for (i = *device; ++i < mdev->devices_count;) {
        if (mdev->devices[i].status == MDEV_ONLINE && mdev->devices[i].sync_status == MDEV_SYNC_STATUS_DONE) {
            *device = i;
            return 1;
        }
    }
    return 0;
}

static int send_mdev_packet(Tox *tox, int32_t dev_num, uint8_t *packet, size_t length)
{
    MDevice *mdev = tox->mdev;

    return write_cryptpacket(tox->net_crypto,
                             toxconn_crypt_connection_id(tox->tox_conn, mdev->devices[dev_num].toxconn_id),
                             packet, length, 0) != -1;
}

static int send_mdev_sync_packet(Tox *tox, int32_t dev_num, uint8_t pkt)
{
    uint8_t packet[ (sizeof(uint8_t) * 2)];

    packet[0] = PACKET_ID_MDEV_SYNC;
    packet[1] = pkt;

    return send_mdev_packet(tox, dev_num, packet, sizeof(packet));
}

static int send_online_packet(Tox *tox, int32_t dev_num, int32_t unused)
{
    if (mdev_device_not_valid(tox->mdev, dev_num)) {
        return 0;
    }

    uint8_t packet = PACKET_ID_ONLINE;
    return send_mdev_packet(tox, dev_num, &packet, sizeof(packet));
}

static int mdev_find_pubkey(Tox *tox, uint8_t *real_pk)
{
    if (public_key_cmp(real_pk, tox->net_crypto->self_public_key) == 0) {
        return MDEV_PUBKEY_STATUS_OURSELF;
    } else if (get_device_id(tox->mdev, real_pk) != -1) {
        return MDEV_PUBKEY_STATUS_OUR_DEVICE;
    } else if (public_key_cmp(real_pk, tox->dht->self_public_key) == 0) {
        return MDEV_PUBKEY_STATUS_OUR_DHT;
    }

    if (getfriend_id(tox->m, real_pk) != -1) {
        if (getfriend_devid(tox->m, real_pk)) {
            return MDEV_PUBKEY_STATUS_FRIENDS_DEVICE;
        }
        return MDEV_PUBKEY_STATUS_FRIEND;
    }

    /* Check if already any the sync list */
    uint32_t dev = UINT32_MAX;
    while (get_next_device_online(tox->mdev, &dev)) {
        uint32_t fid, did;
        for (fid = 0; fid < tox->mdev->devices[dev].sync_friendlist_size; ++fid) {
            Friend *f = &tox->mdev->devices[dev].sync_friendlist[fid];
            for (did = 0; did < f->dev_count; ++did) {
                if (id_equal(real_pk, f->dev_list[did].real_pk)) {
                    return MDEV_PUBKEY_STATUS_IN_SYNCLIST;
                }
            }
        }
    }

    /* TODO: any place else to check? */

    /* Key not found */
    return MDEV_PUBKEY_STATUS_NOTFOUND;
}

static int handle_status(void *object, int dev_num, int device_id, uint8_t status);
static int handle_packet(void *object, int dev_num, int device_id, uint8_t *temp, uint16_t len);
static int handle_custom_lossy_packet(void *object, int dev_num, int device_id, const uint8_t *packet, uint16_t length);

static int32_t init_new_device_self(Tox *tox, const uint8_t* name, size_t length, const uint8_t *real_pk,
                                    uint8_t status)
{
    if (length > MAX_NAME_LENGTH) {
        return FAERR_TOOLONG;
    }

    if (!name && length) {
        return FAERR_TOOLONG;
    }

    /* Resize the friend list if necessary. */
    if (realloc_mdev_list(tox->mdev, tox->mdev->devices_count + 1) != 0) {
        return FAERR_NOMEM;
    }

    memset(&(tox->mdev->devices[tox->mdev->devices_count]), 0, sizeof(Device));

    int devconn_id = new_tox_conn(tox->tox_conn, real_pk);

    if (devconn_id == -1) {
        return FAERR_NOMEM;
    }

    off_t i = tox->mdev->devices_count;
    tox->mdev->devices_count++;
    tox->mdev->devices[i].status = status;
    tox->mdev->devices[i].toxconn_id = devconn_id;

    id_copy(tox->mdev->devices[i].real_pk, real_pk);

    toxconn_set_callbacks(tox->tox_conn,
                          devconn_id,
                          MDEV_CALLBACK_INDEX,
                          &handle_status,
                          &handle_packet,
                          &handle_custom_lossy_packet,
                          tox,
                          i,  /* device number */
                          0); /* sub_device number always 0 for mdevice, */

    if (toxconn_is_connected(tox->tox_conn, devconn_id) == TOXCONN_STATUS_CONNECTED) {
        tox->mdev->devices[i].status = MDEV_ONLINE;
        send_online_packet(tox, i, 0);
    }

    tox->mdev->devices[i].name_length = length;
    memcpy(tox->mdev->devices[i].name, name, length);

    return i;
}

static void set_mdevice_status(MDevice *mdev, uint32_t dev_num, MDEV_STATUS status)
{
    mdev->devices[dev_num].status = status;

    if (status == MDEV_CONFIRMED) {
        mdev->devices[dev_num].sync_status = 0;
    } else if (status == MDEV_ONLINE) {
        /* TODO stuff here */
    }
}

/******************************************************************************
 ******** Multi-device sync helpers                                    ********
 ******************************************************************************/

/* Verifies that everything is in place and ready to sync data.
 *
 * Returns true if everything is ready,
 * Ruturns false if something is in an unexpected state  */
static bool sync_allowed(Tox *tox, MDEV_INTERN_SYNC_ERR *error)
{
    if (!tox->m->friend_list_change) {
        printf("callback not set\n");
        SET_ERROR_PARAMETER(error, MDEV_INTERN_SYNC_ERR_CALLBACK_NOT_SET);
        return 0;
    }

    return 1;
}

/** starts the sync process, be sending the other device our uptime.
 *
 * The device with the longest uptime will be the host (sending data first),
 * with the younger device sending data following
 *
 * The sync order should follow the MDEV_PACKET_TYPE enum in MDevice.h
 * First the Basic user status/state from Messenger.
 * Followed by syncing the friend list.
 * Finally syncing the device network.
 */
static int init_sync(Tox *tox, uint32_t dev_num)
{
    if (!sync_allowed(tox, NULL)) {
        return -1;
    }

    tox->mdev->devices[dev_num].sync_status  = MDEV_SYNC_STATUS_ACTIVE;

    uint8_t packet[ (sizeof(uint8_t) * 2) + sizeof(tox->uptime) ];

    packet[0] = PACKET_ID_MDEV_SYNC;
    packet[1] = MDEV_SYNC_META_UPTIME;

    unix_time_update();
    uint64_t our_uptime = (unix_time() - tox->uptime);

    uint8_t uptime[sizeof(uint64_t)];
    memcpy(uptime, &our_uptime, sizeof(uint64_t));
    host_to_net(uptime, sizeof(uint64_t));
    memcpy(&packet[2], uptime, sizeof(uint64_t));

    return send_mdev_packet(tox, dev_num, packet, sizeof(packet));
}

/** cleans up the sync process if the peer goes offline before the sync
 *  successfully completes */
static int decon_sync(MDevice *mdev, uint32_t dev_num)
{
    if (mdev->devices[dev_num].status != MDEV_ONLINE) {
        /* Handle this error state. */
        mdev->devices[dev_num].sync_status   = MDEV_SYNC_STATUS_NONE;
    } else {
        mdev->devices[dev_num].sync_status   = MDEV_SYNC_STATUS_DONE;
    }

    mdev->devices[dev_num].sync_role     = MDEV_SYNC_ROLE_NONE;

    free(mdev->devices[dev_num].sync_friendlist);
    mdev->devices[dev_num].sync_friendlist           = NULL;
    mdev->devices[dev_num].sync_friendlist_size      = 0;
    mdev->devices[dev_num].sync_friendlist_capacity  = 0;

    return 0;
}

static int init_sync_friends(Tox *tox, uint32_t dev_num)
{
    if (!sync_allowed(tox, NULL)) {
        return -1;
    }
    Messenger  *m = tox->m;

    uint8_t packet[ (sizeof(uint8_t) * 2) + sizeof(m->numfriends)];

    packet[0] = PACKET_ID_MDEV_SYNC;
    packet[1] = MDEV_SYNC_CONTACT_COUNT;

    uint8_t numfriends[sizeof(m->numfriends)];
    memcpy(numfriends, &(m->numfriends), sizeof(uint32_t));
    host_to_net(numfriends, sizeof(uint32_t));
    memcpy(&packet[2], numfriends, sizeof(uint32_t));

    return send_mdev_packet(tox, dev_num, packet, sizeof(packet));
}

static int init_sync_devices(Tox *tox, uint32_t dev_num)
{
    if (!sync_allowed(tox, NULL)) {
        return -1;
    }
    MDevice *mdev = tox->mdev;

    uint8_t packet[ (sizeof(uint8_t) * 2) + sizeof(mdev->devices_count)];

    packet[0] = PACKET_ID_MDEV_SYNC;
    packet[1] = MDEV_SYNC_DEVICE_COUNT;

    uint8_t device_count[sizeof(mdev->devices_count)];
    memcpy(device_count, &(mdev->devices_count), sizeof(uint32_t));
    host_to_net(device_count, sizeof(uint32_t));
    memcpy(&packet[2], device_count, sizeof(uint32_t));

    return send_mdev_packet(tox, dev_num, packet, sizeof(packet));
}

static int request_friend_sync(Tox *tox, uint32_t dev_num)
{
    if (!sync_allowed(tox, NULL)) {
        return -1;
    }

    tox->mdev->devices[dev_num].sync_status = MDEV_SYNC_STATUS_FRIENDS_RECIVING;

    return send_mdev_sync_packet(tox, dev_num, MDEV_SYNC_CONTACT_START);
}

static int sync_friend_commit(Tox *tox, uint32_t dev_num)
{
    if (!sync_allowed(tox, NULL)) {
        return -1;
    }

    /* There are some short cuts taken in here, such as not cleaning up the existing list.
     * This is by design. E.g. m_addfriend_norequest() will create a new connection, but this will become the original
     * connection for that pubkey, (assuming one already exists). */

     /* TODO, we shouldn't commit, and send the callback, if the list was already in sync */

    Messenger  *m = tox->m;
    MDevice *mdev = tox->mdev;

    if (realloc_friendlist(m, 0) == -1){
        send_mdev_sync_packet(tox, dev_num, MDEV_SYNC_CONTACT_ERROR);
        return -1;
    }
    m->numfriends = 0;

    uint32_t i;

    for (i = 0; i < mdev->devices[dev_num].sync_friendlist_size; ++i) {

        Friend *temp = &mdev->devices[dev_num].sync_friendlist[i];

        /* TODO this will increment the lock count for this connection for this contact.
         * and I haven't verified that this is okay.
         *
         * It would be safer, to close the tox_conn here, but I'm also not convinced that's
         * required, or the right thing to do either. */
        int fnum = m_addfriend_norequest(tox, &temp->dev_list[0].real_pk[0]);

        if (fnum < 0) {
            /* TODO can re really just continue here? */
            continue;
        }

        setfriendname(m, fnum, temp->name, temp->name_length);
        set_friend_statusmessage(m, fnum, temp->statusmessage, temp->statusmessage_length);
        set_friend_userstatus(m, fnum, temp->userstatus);
        m->friendlist[fnum].last_seen_time = temp->last_seen_time;

        printf("friend added %u \n", i);
    }

    decon_sync(mdev, dev_num);

    return 0;
}

/******************************************************************************
 ******** Multi-device sync INCOMING                                   ********
 ******************************************************************************/

/** If @device is TRUE, it's an additional public_key/device for the last sent
 *  contact and not a new friend */
static int sync_friend_recived(Tox *tox, uint32_t dev_num, uint8_t *real_pk, bool device)
{
    if (!sync_allowed(tox, NULL)) {
        printf("unable to sync, this is bad\n");
        return -1;
    }

    MDevice *mdev = tox->mdev;
    Messenger  *m = tox->m;

    /* I really wanted to do something simple here, but that's clearly not really an option :<
     * This will be very interesting to maintain... */

    Friend *friend = &mdev->devices[dev_num].sync_friendlist[mdev->devices[dev_num].sync_friendlist_size];
    uint32_t dev_position = 0;


    switch (mdev_find_pubkey(tox, real_pk)) {
        case MDEV_PUBKEY_STATUS_OURSELF:
        case MDEV_PUBKEY_STATUS_OUR_DEVICE:
        case MDEV_PUBKEY_STATUS_OUR_DHT: {
            /* we can't work with this PK for ... reasons */
            return -1;
        }

        case MDEV_PUBKEY_STATUS_FRIEND: { /* existing friend */
            printf("existing friend\n");
            if (device) {
                /* error here, can't add a device_pk when we already know this friend */
                    /* corner case, handling pre-existing friends that need to be grouped together */
                break;
            }

            int32_t id = getfriend_id(m, real_pk);

            memcpy(friend->name, m->friendlist[id].name, m->friendlist[id].name_length);
            friend->name_length = m->friendlist[id].name_length;

            memcpy(friend->statusmessage, m->friendlist[id].statusmessage, m->friendlist[id].statusmessage_length);
            friend->statusmessage_length = m->friendlist[id].statusmessage_length;

            friend->userstatus = m->friendlist[id].userstatus;
            friend->last_seen_time =  m->friendlist[id].last_seen_time;
            break;
        }

        case MDEV_PUBKEY_STATUS_FRIENDS_DEVICE: {
            /* existing device */
            if (!device) {
                /* A friend already controls this device, but our peer says this is only a friend */
                    /* corner case, handling pre-existing friends that need to be grouped together */
                break;
            }
            dev_position = getfriend_devid(m, real_pk);

            /* We're going to increment, but shouldn't on devices, so let's cheat a bit */
            tox->mdev->devices[dev_num].sync_friendlist_size--;
            break;
        }

        case MDEV_PUBKEY_STATUS_IN_SYNCLIST: {
            /* this is a duplicate pub key */
            return -1;
            /* TODO different return number? */
        }

    }

    if (realloc_friend_dev_list(mdev, dev_num, mdev->devices[dev_num].sync_friendlist_size, 1)) {
        printf("couldn't alloc for this devices... sorry mate!\n");
        return -1;
    }

    id_copy(friend->dev_list[dev_position].real_pk, real_pk);
    mdev->devices[dev_num].sync_friendlist_size++;

    return 0;
}

/******************************************************************************
 ******** Multi-device sync OUTGOING                                   ********
 ******************************************************************************/

/** TODO DOCUMENT THIS FXN
 *
 *
 *
 *
 */
static int actually_send_friend_list(Tox *tox, uint32_t dev_num)
{
    if (!sync_allowed(tox, NULL)) {
        return -1;
    }

    if (tox->m->numfriends == 0) {
        if (send_mdev_sync_packet(tox, dev_num, MDEV_SYNC_CONTACT_DONE)) {
            return -1;
        } else {
            return 0;
        }
    }

    int i;
    uint8_t packet[sizeof(uint8_t) * 2 + sizeof(uint8_t) * crypto_box_PUBLICKEYBYTES];

    for (i = 0; i < tox->m->numfriends; ++i) {
        if (!tox->m->friendlist[i].status) {
            /* Currently we sync all friends who we've send a friend request to.
               Q: do we want to be "< FRIEND_CONFIRMED?"  So we only send to
                  confirmed friends?
               We don't (yet) sync the nospam, or the friend request message */
            continue;
        }

        memset(packet, 0, sizeof(packet));

        packet[0] = PACKET_ID_MDEV_SYNC;
        packet[1] = MDEV_SYNC_CONTACT_APPEND;

        memcpy(packet + 2, tox->m->friendlist[i].dev_list[0].real_pk, crypto_box_PUBLICKEYBYTES);

        if (!send_mdev_packet(tox, dev_num, packet, sizeof(packet))) {
            printf("ERROR sending MDEV_SYNC_CONTACT_APPEND packet \n");
            return -2;
        }

        sync_friend_recived(tox, dev_num, tox->m->friendlist[i].dev_list[0].real_pk, 0);
    }

    if (!send_mdev_sync_packet(tox, dev_num, MDEV_SYNC_CONTACT_DONE)) {
        return -3;
    }

    return 0;
}

static int handle_status(void *object, int dev_num, int device_id, uint8_t status)
{
    Tox *tox = object;
    MDevice *mdev = tox->mdev;

    if (dev_num < 0 || dev_num > UINT32_MAX || (uint32_t)dev_num >= mdev->devices_count)
        return -1;

    printf("handle_status MDEV dev_num %i || dev_id %i || status %u \n", dev_num, device_id, status);
    if (status) {
        set_mdevice_status(mdev, dev_num, MDEV_ONLINE);

        init_sync(tox, dev_num);
    } else {
        set_mdevice_status(mdev, dev_num, MDEV_CONFIRMED);
        decon_sync(mdev, dev_num);
    }
    return 0;
}

static int handle_packet_send(Tox *tox, uint32_t dev_num, uint8_t *pkt, uint16_t length)
{
    MDevice *mdev = tox->mdev;

    switch (pkt[0]) {
        case MDEV_SEND_SELF_NAME: {
            uint8_t *name        = pkt + 1;
            size_t   name_length = length - 1;

            if (name_length > MAX_NAME_LENGTH) {
                return -1;
            }

            if (name_length > MAX_NAME_LENGTH) {
                return -1;
            }

            if (tox->m->name_length == name_length && (name_length == 0 || memcmp(name, tox->m->name, name_length) == 0)) {
                return -1;
            }

            if (name_length) {
                memcpy(tox->m->name, name, name_length);
            }

            tox->m->name_length = name_length;

            if (mdev->self_name_change) {
                mdev->self_name_change(tox, dev_num, name, name_length, mdev->self_name_change_userdata);
            }

            break;
        }

        case MDEV_SEND_SELF_STATUS_MSG: {
            uint8_t *status        = pkt + 1;
            size_t   status_length = length - 1;

            if (status_length > MAX_NAME_LENGTH) {
                break;
            }

            if (status_length > MAX_STATUSMESSAGE_LENGTH) {
                break;
            }

            if (status_length) {
                memcpy(tox->m->statusmessage, status, status_length);
            }

            tox->m->statusmessage_length = status_length;

            if (mdev->self_status_message_change) {
                mdev->self_status_message_change(tox, dev_num, status, status_length,
                                                 mdev->self_status_message_change_userdata);
            }

            break;
        }

        case MDEV_SEND_SELF_STATE: {
            if (length != 2) {
                return -1;
            }

            if (pkt[1] >= USERSTATUS_INVALID) {
                return -1;
            }

            if (mdev->self_user_state_change) {
                mdev->self_user_state_change(tox, dev_num, pkt[1], mdev->self_user_state_change_userdata);
            } else {
                return -1;
            }

            break;
        }

        case MDEV_SEND_MESSAGE:
        case MDEV_SEND_MESSAGE_ACTION: {
            if (mdev->mdev_sent_message) {

                if (length <= sizeof(uint32_t) + 1) {
                    return -1;
                }

                uint32_t target;
                uint8_t tmp_fr_num[sizeof(uint32_t)];
                memcpy(tmp_fr_num, &pkt[1], sizeof(uint32_t));
                host_to_net(tmp_fr_num, sizeof(uint32_t));
                memcpy(&target, tmp_fr_num, sizeof(uint32_t));

                bool type = (pkt[0] - MDEV_SEND_MESSAGE);

                uint8_t *message = &pkt[1 + sizeof(uint32_t)];

                size_t message_length = length - sizeof(uint32_t) - 1;

                mdev->mdev_sent_message(tox, dev_num, target, type, message, message_length);
            }

            break;
        }

        default: {
            printf("mdev packet_send with unsupported type %u\n", pkt[0]);
            break;
        }
    }

    return 0;
}

static int handle_packet_sync(Tox *tox, uint32_t dev_num, uint8_t *pkt, uint16_t size)
{
    switch (pkt[0]) {
        case MDEV_SYNC_META: {
            printf("SYNC_META is unsupported in this build, please update your toxcore\n");
            return -1;
        }

        case MDEV_SYNC_META_UPTIME: {

            if ( (size - 1) < sizeof(tox->uptime) ) {
                return -1;
            }

            unix_time_update();
            uint64_t us   = (unix_time() - tox->uptime);

            uint64_t them;

            uint8_t them_time[sizeof(uint64_t)];
            memcpy(them_time, &pkt[1], sizeof(uint64_t));
            net_to_host(them_time, sizeof(uint64_t));
            memcpy(&them, them_time, sizeof(uint64_t));


            printf("their uptime %lu our uptime %lu \n", them, us);
            /* TODO handle == differently */
            if (us > them) {
                tox->mdev->devices[dev_num].sync_role    = MDEV_SYNC_ROLE_PRIMARY;
                tox->mdev->devices[dev_num].sync_status  = MDEV_SYNC_STATUS_FRIENDS_SENDING;
                init_sync_friends(tox, dev_num);
            } else {
                tox->mdev->devices[dev_num].sync_role    = MDEV_SYNC_ROLE_SECONDARY;
                tox->mdev->devices[dev_num].sync_status  = MDEV_SYNC_STATUS_FRIENDS_RECIVING;
                init_sync_friends(tox, dev_num);
            }

            break;
        }

        case MDEV_SYNC_SELF_NAME: {
            printf("recv: %u\n", pkt[1]);
            break;
        }

        case MDEV_SYNC_SELF_STATUS_MSG: {
            printf("recv: %u\n", pkt[1]);
            break;
        }

        case MDEV_SYNC_SELF_STATE: {
            printf("recv: %u\n", pkt[1]);
            break;
        }

        case MDEV_SYNC_SELF_DONE: {
            printf("recv: %u\n", pkt[1]);
            break;
        }

        case MDEV_SYNC_CONTACT_START: {
            if (size != 1) {
                return -1;
            }

            if (!tox->mdev->devices[dev_num].sync_role) {
                printf("they're requesting a friend sync, but we don't have a role. this is bad\n");
            }

            actually_send_friend_list(tox, dev_num);

            /* TODO if actually_send_friend_list != 0 handle the error somehow... */
            break;
        }

        case MDEV_SYNC_CONTACT_COUNT: {
            if ( (size - 1) < sizeof(tox->m->numfriends) ) {
                return -1;
            }

            /* TODO error checking */
            /* TODO overflow checking */

            uint32_t their_friend_count = pkt[1];
            printf("they have %u friends we have %u friends\n", their_friend_count, tox->m->numfriends);
            int total = their_friend_count + tox->m->numfriends;
            tox->mdev->devices[dev_num].sync_friendlist = calloc(total, sizeof(Friend));
            if (tox->mdev->devices[dev_num].sync_friendlist) {
                if (tox->mdev->devices[dev_num].sync_role == MDEV_SYNC_ROLE_SECONDARY) {
                    request_friend_sync(tox, dev_num);
                }
            } else {
                send_mdev_sync_packet(tox, dev_num, MDEV_SYNC_CONTACT_ERROR);
                return -1;
            }

            break;
        }

        case MDEV_SYNC_CONTACT_APPEND:
        case MDEV_SYNC_CONTACT_APPEND_DEVICE: {
            if ( (size -1) != crypto_box_PUBLICKEYBYTES) {
                return -1;
            }

            bool device = (pkt[0] == MDEV_SYNC_CONTACT_APPEND_DEVICE);
            uint8_t *pk = &pkt[1];

            sync_friend_recived(tox, dev_num, pk, device);
            break;
        }

        case MDEV_SYNC_CONTACT_REMOVE: {
            printf("they deleted friend ... does nothing\n");
            break;
        }

        case MDEV_SYNC_CONTACT_REJECT: {
            printf("they rejected a friend change ... does nothing\n");
            /* TODO revert all pending changes */
            break;
        }

        case MDEV_SYNC_CONTACT_DONE: {
            if (tox->mdev->devices[dev_num].sync_role == MDEV_SYNC_ROLE_SECONDARY) {
                tox->mdev->devices[dev_num].sync_status = MDEV_SYNC_STATUS_FRIENDS_SENDING;
                actually_send_friend_list(tox, dev_num);
            } else if (tox->mdev->devices[dev_num].sync_role == MDEV_SYNC_ROLE_PRIMARY) {
                tox->mdev->devices[dev_num].sync_status  = MDEV_SYNC_STATUS_DONE;
                if (send_mdev_sync_packet(tox, dev_num, MDEV_SYNC_CONTACT_COMMIT)){
                    sync_friend_commit(tox, dev_num);
                    if (tox->m->friend_list_change) {
                        tox->m->friend_list_change(tox, tox->m->friend_list_change_userdata);
                    }
                }
            } else {
                printf("we're neither, this is really bad!\n");
                return -1;
            }

            break;
        }

        case MDEV_SYNC_CONTACT_COMMIT: {
            printf("commit packet received, going to commit!\n");
            if (tox->mdev->devices[dev_num].sync_role == MDEV_SYNC_ROLE_SECONDARY) {
                sync_friend_commit(tox, dev_num);
                if (tox->m->friend_list_change) {
                    tox->m->friend_list_change(tox, tox->m->friend_list_change_userdata);
                }
            }
            break;
        }

        case MDEV_SYNC_DEVICE_COUNT: {
            printf("%d", pkt[1]);
            break;
        }
    }

    return 0;
}

static int handle_packet(void *object, int dev_num, int device_id, uint8_t *pkt, uint16_t len)
{
    printf("handle_packet MDEV dev_num %i // dev_id %i // pkt %u // length %u \n", dev_num, device_id, pkt[0], len);

    if (len == 0) {
        return -1;
    }

    Tox      *tox = object;
    MDevice *mdev = tox->mdev;

    if (dev_num < 0 || dev_num > UINT32_MAX || (uint32_t)dev_num >= mdev->devices_count)
        return -1;

    uint8_t packet_id = pkt[0];
    uint8_t *data = pkt + 1;
    uint32_t data_length = len - 1;

    if (mdev->devices[dev_num].status != MDEV_ONLINE) {
        if (packet_id == PACKET_ID_ONLINE && len == 1) {
            set_mdevice_status(mdev, dev_num, MDEV_ONLINE);
            send_online_packet(tox, dev_num, 0);
        } else {
            printf("error, this device is offline\n");
            return -1;
        }
    }

    if (packet_id == PACKET_ID_OFFLINE) {
        if (data_length != 0) {
            return -1;
        } else {
            set_mdevice_status(mdev, dev_num, MDEV_CONFIRMED);
        }
    } else if (packet_id == PACKET_ID_MDEV_SEND) {
        return handle_packet_send(tox, dev_num, data, len -1);
    } else if (packet_id == PACKET_ID_MDEV_SYNC) {
        return handle_packet_sync(tox, dev_num, data, len -1);
    } else {
        printf("ERROR MDevice unknown packet type %u\n", packet_id);
        return -1;
    }

    return 0;
}


static int handle_custom_lossy_packet(void *object, int dev_num, int device_id, const uint8_t *packet, uint16_t length)
{
    Tox *tox = object;
    printf("handle_custom_lossy_packet MDEV\n");
    return 0;
}

/******************************************************************************
 ******** Multi-device send data fxns                                  ********
 ******************************************************************************/
bool mdev_send_name_change(Tox *tox, const uint8_t *name, size_t length)
{
    uint8_t packet[length + 2];

    packet[0] = PACKET_ID_MDEV_SEND;
    packet[1] = MDEV_SEND_SELF_NAME;
    memcpy(&packet[2], name, length);

    if (tox->mdev->devices_count == 0) {
        return 0;
    }

    uint32_t dev = UINT32_MAX;
    while (get_next_device_online(tox->mdev, &dev)) {
        send_mdev_packet(tox, dev, packet, length + 2);
    }

    return 1;
}

bool mdev_send_status_message_change(Tox *tox, const uint8_t *status, size_t length)
{
    uint8_t packet[length + 2];

    packet[0] = PACKET_ID_MDEV_SEND;
    packet[1] = MDEV_SEND_SELF_STATUS_MSG;
    memcpy(&packet[2], status, length);

    if (tox->mdev->devices_count == 0) {
        return 0;
    }

    uint32_t dev = UINT32_MAX;
    while (get_next_device_online(tox->mdev, &dev)) {
        send_mdev_packet(tox, dev, packet, length + 2);
    }

    return 1;
}

bool mdev_send_state_change(Tox *tox, const TOX_USER_STATUS state)
{
    if (tox->mdev->devices_count == 0) {
        return 0;
    }

    uint8_t packet[3];

    packet[0] = PACKET_ID_MDEV_SEND;
    packet[1] = MDEV_SEND_SELF_STATE;
    packet[2] = state;

    uint32_t dev = UINT32_MAX;
    while (get_next_device_online(tox->mdev, &dev)) {
        send_mdev_packet(tox, dev, packet, 3);
    }

    return 1;
}


int mdev_send_message_generic(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message,
                               size_t length)
{
    if (length >= MAX_CRYPTO_DATA_SIZE - 2) {
        return -2;
    }

    uint8_t packet[length + 2];
    packet[0] = PACKET_ID_MDEV_SEND;
    packet[1] = MDEV_SEND_MESSAGE + type;

    uint8_t friend_num[sizeof(uint32_t)];
    memcpy(friend_num, &friend_number, sizeof(uint32_t));
    host_to_net(friend_num, sizeof(uint32_t));
    memcpy(&packet[2], friend_num, sizeof(uint32_t));

    if (length != 0) {
        memcpy(packet + 2 + sizeof(uint32_t), message, length);
    }

    uint32_t dev = UINT32_MAX;
    while(get_next_device_synced(tox->mdev, &dev)) {
        int crypt_con_id = toxconn_crypt_connection_id(tox->tox_conn, tox->mdev->devices[dev].toxconn_id);
        write_cryptpacket(tox->net_crypto, crypt_con_id, packet, length + 2 + sizeof(uint32_t), 0);
    }

    return 0;
}



/******************************************************************************
 ******** Multi-device Exposed API functions                           ********
 ******************************************************************************/
int32_t mdev_get_dev_count(Tox *tox)
{
    if (!tox || !tox->mdev) {
        return 0;
    }

    return get_device_count(tox->mdev);
}

/* returns 1 on success, and 0 on failure */
bool mdev_get_dev_pubkey(Tox *tox, uint32_t number, uint8_t pk[crypto_box_PUBLICKEYBYTES])
{
    if (!tox || !tox->mdev) {
        return 0;
    }

    if (!pk) {
        return 0;
    }

    if (!tox->mdev->devices_count || number > tox->mdev->devices_count - 1) {
        return 0;
    }

    if (tox->mdev->devices[number].status) {
        id_copy(pk, tox->mdev->devices[number].real_pk);
        return 1;
    }

    return 0;
}


/******************************************************************************
 ******** Multi-device set callbacks                                   ********
 ******************************************************************************/
void mdev_callback_self_name(Tox *tox, tox_mdev_self_name_cb *fxn, void *userdata)
{
    tox->mdev->self_name_change = fxn;
    tox->mdev->self_name_change_userdata = userdata;
}

void mdev_callback_self_status_message(Tox *tox, tox_mdev_self_status_message_cb *fxn, void *userdata)
{
    tox->mdev->self_status_message_change = fxn;
    tox->mdev->self_status_message_change_userdata = userdata;
}

void mdev_callback_self_state(Tox *tox, tox_mdev_self_state_cb *fxn, void *userdata)
{
    tox->mdev->self_user_state_change = fxn;
    tox->mdev->self_user_state_change_userdata = userdata;
}

void mdev_callback_mdev_sent_message(Tox *tox, tox_mdev_sent_message_cb *fxn, void *userdata)
{
    tox->mdev->mdev_sent_message = fxn;
    tox->mdev->mdev_sent_message_userdata = userdata;
}

/******************************************************************************
 ******** Multi-device init, exit fxns                                 ********
 ******************************************************************************/

/* TODO replace the options here with our own! */
MDevice *new_mdevice(Tox* tox, MDevice_Options *options, unsigned int *error)
{
    MDevice *dev = calloc(1, sizeof(MDevice));

    SET_ERROR_PARAMETER(error, MESSENGER_ERROR_OTHER);

    if (!dev) {
        return NULL;
    }

    dev->options = *options;
    SET_ERROR_PARAMETER(error, MESSENGER_ERROR_NONE);
    return dev;
}

/* Run this before closing shop. */
void kill_multidevice(MDevice *dev)
{
    if (!dev) {
        return;
    }

    uint32_t i;

    free(dev->devices);
    free(dev);
}



void do_multidevice(Tox *tox)
{
    if (!tox || !tox->mdev) {
        return;
    }


    /* we should probably do things here... */
}

static int get_device_id(MDevice *dev, const uint8_t *real_pk)
{
    uint32_t i;

    for (i = 0; i < dev->devices_count; ++i) {
        if (id_equal(real_pk, dev->devices[i].real_pk)) {
            return i;
        }
    }

    return -1;
}

static int get_removed_device_id(MDevice *dev, const uint8_t *real_pk)
{
    uint32_t i;

    for (i = 0; i < dev->removed_devices_count; ++i) {
        if (id_equal(real_pk, dev->removed_devices[i])) {
            return i;
        }
    }

    return -1;
}

int mdev_add_new_device_self(Tox *tox, const uint8_t* name, size_t length, const uint8_t *real_pk)
{
    if (!public_key_valid(real_pk)) {
        return -2;
    }

    if (public_key_cmp(real_pk, tox->net_crypto->self_public_key) == 0) {
        return -3;
    } else if (public_key_cmp(real_pk, tox->dht->self_public_key) == 0) {
        return -3;
    }

    if (get_removed_device_id(tox->mdev, real_pk) >= 0) {
        printf("Dev ID is blacklisted!\n");
        return -4;
    }

    int32_t dev_id = get_device_id(tox->mdev, real_pk);

    if (dev_id != -1) {
        printf("Dev ID Already exists in list...\n");
        return -5;
    }

    int32_t ret = init_new_device_self(tox, name, length, real_pk, MDEV_PENDING);

    return ret;
}

static size_t mdev_devices_size(MDevice* self)
{
    size_t size = 0, devi;
    for (devi = 0; devi < self->devices_count; ++devi) {
        Device* dev = &self->devices[devi];
        size +=   sizeof(uint8_t)
                + sizeof(dev->real_pk)
                + sizeof(dev->last_seen_time)
                + sizeof(uint16_t)
                + dev->name_length;
    }
    return size;
}

size_t mdev_size(const Tox *tox)
{
    if (!tox->mdev) {
        return 0;
    }

    return    save_subheader_size()                                         /* Section header */
            + sizeof(uint8_t)                                               /* Version field */
            + sizeof(tox->mdev->devices_count)                              /* Device count */
            + mdev_devices_size(tox->mdev)                                  /* Device data */
            + sizeof(tox->mdev->removed_devices_count)                      /* Removed device count */
            + tox->mdev->removed_devices_count*crypto_box_PUBLICKEYBYTES    /* Removed device data */
            ;
}

uint8_t *mdev_save(const Tox *tox, uint8_t *data)
{
    size_t len = mdev_size(tox) - save_subheader_size();
    data = save_write_subheader(data, len, SAVE_STATE_TYPE_MDEVICE, SAVE_STATE_COOKIE_TYPE);

    *data++ = 0; /* Current version of the on-disk format */

    host_to_lendian32(data, tox->mdev->devices_count);
    data += sizeof(uint32_t);

    size_t devi;
    for (devi = 0; devi < tox->mdev->devices_count; ++devi) {
        Device* dev = &tox->mdev->devices[devi];

        *data++ = dev->status;

        memcpy(data, dev->real_pk, sizeof(dev->real_pk));
        data += sizeof(dev->real_pk);

        uint16_t len = host_tolendian16(dev->name_length);
        memcpy(data, &len, sizeof(uint16_t));
        data += sizeof(uint16_t);
        memcpy(data, dev->name, dev->name_length);
        data += dev->name_length;

        uint8_t last_seen_time[sizeof(uint64_t)];
        memcpy(last_seen_time, &dev->last_seen_time, sizeof(uint64_t));
        host_to_net(last_seen_time, sizeof(last_seen_time));
        memcpy(data, last_seen_time, sizeof(last_seen_time));
        data += sizeof(last_seen_time);
    }

    host_to_lendian32(data, tox->mdev->removed_devices_count);
    data += sizeof(uint32_t);

    size_t size = tox->mdev->removed_devices_count * crypto_box_PUBLICKEYBYTES;
    memcpy(data, tox->mdev->removed_devices, size);
    data += size;

    return data;
}

int mdev_save_read_sections_callback(Tox *tox, const uint8_t *data, uint32_t length, uint16_t type)
{
    if (type != SAVE_STATE_TYPE_MDEVICE)
        return 0;

    if (length < sizeof(uint8_t))
        return -1;
    uint8_t version = data[0];
    data++;
    length--;

    MDevice* self = tox->mdev;

    if (version == 0) {
        if (length < sizeof(uint32_t))
            return 0;
        length -= sizeof(uint32_t);

        uint32_t devices_count;
        lendian_to_host32(&devices_count, data);
        self->devices_count = 0;
        data += sizeof(uint32_t);

        size_t devi;
        for (devi = 0; devi < devices_count; ++devi) {
            uint8_t status;
            uint8_t real_pk[crypto_box_PUBLICKEYBYTES];
            uint8_t     name[MAX_NAME_LENGTH];
            uint16_t    name_length;

            size_t required = sizeof(uint8_t)+sizeof(real_pk)+sizeof(uint16_t);
            if (length < required)
                goto fail_tooshort;
            length -= required;

            status = (MDEV_STATUS)*data++;

            memcpy(real_pk, data, sizeof(real_pk));
            data += sizeof(real_pk);

            memcpy(&name_length, data, sizeof(uint16_t));
            name_length = lendian_to_host16(name_length);
            data += sizeof(uint16_t);
            if (length < name_length)
                goto fail_tooshort;
            length -= name_length;
            memcpy(name, data, name_length);
            data += name_length;

            if (mdev_add_new_device_self(tox, name, length, real_pk) < 0)
                goto fail_generic;

            Device* dev = &self->devices[devi];

            dev->status = status;

            if (length < sizeof(uint64_t))
                goto fail_tooshort;
            length -= sizeof(uint64_t);

            uint8_t last_seen_time[sizeof(uint64_t)];
            memcpy(last_seen_time, data, sizeof(last_seen_time));
            net_to_host(last_seen_time, sizeof(last_seen_time));
            memcpy(&dev->last_seen_time, last_seen_time, sizeof(uint64_t));
            data += sizeof(last_seen_time);
        }

        if (length < sizeof(uint32_t))
            goto fail_tooshort;
        length -= sizeof(uint32_t);

        lendian_to_host32(&self->removed_devices_count, data);
        data += sizeof(uint32_t);

        size_t removed_size = self->removed_devices_count * crypto_box_PUBLICKEYBYTES;
        if (length < removed_size)
            goto fail_tooshort;
        length -= removed_size;
        if (realloc_mdev_removed_list(self, self->removed_devices_count) < 0)
            goto fail_generic;
        memcpy(self->removed_devices, data, removed_size);
        data += removed_size;

        if (length)
            printf("mdev_save_read_sections_callback: Extra data ignored, save might be corrupted!\n");
    }

    return 0;

fail_tooshort:
    printf("Failed to read MDevice saved state, data is truncated!\n");
fail_generic:
    realloc_mdev_list(self, 0);
    self->devices_count = 0;
    return 0;
}

int mdev_remove_device(Tox *tox, const uint8_t *address)
{
    MDevice* self = tox->mdev;

    int device_num = get_device_id(tox->mdev, address);
    if (device_num < 0)
        return -1;

    if (get_removed_device_id(self, address) < 0) {
        realloc_mdev_removed_list(self, self->removed_devices_count+1);
        memcpy(self->removed_devices[self->removed_devices_count], self->devices[device_num].real_pk,
                sizeof(self->devices[device_num].real_pk));
        self->removed_devices_count++;
    }

    off_t pos = device_num*sizeof(Device), new_pos = pos-sizeof(Device);
    size_t size = (self->devices_count - device_num - 1)*sizeof(Device);
    memmove(self->devices+new_pos, self->devices+pos, size);
    realloc_mdev_list(self, self->devices_count-1); // Not a problem if it fails to shrink
    self->devices_count--;

    return 0;
}
