/** MDevice.c
 *
 * Multidevice interface for Toxcore
 *
 */

#include "MDevice.h"
#include "util.h"

static int realloc_mdev_list(MDevice *dev, uint32_t num)
{
    if (num == 0) {
        free(dev->device);
        dev->device = NULL;
        return 0;
    }

    Device *new_dev_list = realloc(dev->device, num * sizeof(Device));

    if (new_dev_list == NULL)
        return -1;

    dev->device = new_dev_list;
    return 0;
}

static uint8_t mdev_device_not_valid(const MDevice *dev, uint32_t dev_num)
{
    if (dev_num < dev->device_count) {
        if (dev->device[dev_num].status > MDEV_OK) {
            return 0;
        }
    }

    return 1;
}

static int send_online_packet(MDevice *dev, int32_t dev_num, int32_t unused)
{
    if (mdev_device_not_valid(dev, dev_num)) {
        return 0;
    }

    uint8_t packet = PACKET_ID_ONLINE;
    return write_cryptpacket(dev->net_crypto,
                             toxconn_crypt_connection_id(dev->dev_conns, dev->device[dev_num].toxconn_id),
                             &packet, sizeof(packet), 0) != -1;
}

static int handle_status(void *object, int dev_num, int device_id, uint8_t status);
static int handle_packet(void *object, int dev_num, int device_id, uint8_t *temp, uint16_t len);
static int handle_custom_lossy_packet(void *object, int dev_num, int device_id, const uint8_t *packet, uint16_t length);

static int32_t init_new_device_self(MDevice *dev, const uint8_t *real_pk, uint8_t status)
{
    /* Resize the friend list if necessary. */
    if (realloc_mdev_list(dev, dev->device_count + 1) != 0) {
        return FAERR_NOMEM;
    }

    memset(&(dev->device[dev->device_count]), 0, sizeof(Device));

    int devconn_id = new_tox_conn(dev->dev_conns, real_pk);

    if (devconn_id == -1) {
        return FAERR_NOMEM;
    }

    uint32_t i;

    for (i = 0; i <= dev->device_count; ++i) {
        if (dev->device[i].status == NO_MDEV) {
            dev->device[i].status = status;
            dev->device[i].toxconn_id = devconn_id;

            id_copy(dev->device[i].real_pk, real_pk);

            toxconn_set_callbacks(dev->dev_conns, devconn_id, MDEV_CALLBACK_INDEX, &handle_status, &handle_packet,
                                  &handle_custom_lossy_packet, dev, i,  /* device number */
                                  0); /* device number always 0 for mdev */

            if (dev->device_count == i) {
                ++dev->device_count;
            }

            if (toxconn_is_connected(dev->dev_conns, devconn_id) == TOXCONN_STATUS_CONNECTED) {
                dev->device[i].status = MDEV_ONLINE;
                send_online_packet(dev, i, 0);
            }

            return i;
        }
    }

    return FAERR_NOMEM;
}

static int handle_status(void *object, int dev_num, int device_id, uint8_t status)
{
    printf("handle_status MDEV\n");
    return 0;
}


static int handle_packet(void *object, int dev_num, int device_id, uint8_t *temp, uint16_t len)
{
    printf("handle_packet MDEV\n");
    return 0;
}


static int handle_custom_lossy_packet(void *object, int dev_num, int device_id, const uint8_t *packet, uint16_t length)
{
    printf("handle_custom_lossy_packet MDEV\n");
    return 0;
}

/* TODO replace the options here with our own! */
MDevice *new_mdevice(Messenger_Options *options, unsigned int *error)
{
    MDevice *dev = calloc(1, sizeof(MDevice));

    if (error) {
        *error = MESSENGER_ERROR_OTHER;
    }

    if (!m) {
        return NULL;
    }

    unsigned int net_err = 0;

    if (options->udp_disabled) {
        /* this is the easiest way to completely disable UDP without changing too much code. */
        dev->net = calloc(1, sizeof(Networking_Core));
    } else {
        IP ip;
        ip_init(&ip, options->ipv6enabled);
        dev->net = new_networking_ex(ip, options->port_range[0], options->port_range[1], &net_err);
    }

    if (dev->net == NULL) {
        free(dev);

        if (error && net_err == 1) {
            *error = MESSENGER_ERROR_PORT;
        }

        return NULL;
    }

    dev->dht = new_DHT(dev->net);

    if (dev->dht == NULL) {
        kill_networking(dev->net);
        free(dev);
        return NULL;
    }

    dev->net_crypto = new_net_crypto(dev->dht, &options->proxy_info);

    if (dev->net_crypto == NULL) {
        kill_networking(dev->net);
        kill_DHT(dev->dht);
        free(dev);
        return NULL;
    }

    dev->onion      = new_onion(dev->dht);
    dev->onion_a    = new_onion_announce(dev->dht);
    dev->onion_c    = new_onion_client(dev->net_crypto);
    dev->fr_c       = new_tox_conns(dev->onion_c);

    if (!(dev->onion && dev->onion_a && dev->onion_c)) {
        kill_tox_conns(dev->fr_c);
        kill_onion(dev->onion);
        kill_onion_announce(dev->onion_a);
        kill_onion_client(dev->onion_c);
        kill_net_crypto(dev->net_crypto);
        kill_DHT(dev->dht);
        kill_networking(dev->net);
        free(dev);
        return NULL;
    }

    if (options->tcp_server_port) {
        dev->tcp_server = new_TCP_server(options->ipv6enabled, 1, &options->tcp_server_port, dev->dht->self_secret_key, dev->onion);

        if (dev->tcp_server == NULL) {
            kill_tox_conns(dev->fr_c);
            kill_onion(dev->onion);
            kill_onion_announce(dev->onion_a);
            kill_onion_client(dev->onion_c);
            kill_net_crypto(dev->net_crypto);
            kill_DHT(dev->dht);
            kill_networking(dev->net);
            free(dev);

            if (error) {
                *error = MESSENGER_ERROR_TCP_SERVER;
            }

            return NULL;
        }
    }

    dev->options = *options;
    friendreq_init(&(dev->fr), dev->fr_c);
    set_nospam(&(dev->fr), random_int());
    set_filter_function(&(dev->fr), &friend_already_added, m);

    if (error) {
        *error = MESSENGER_ERROR_NONE;
    }

    return m;
}

/* Run this before closing shop. */
void kill_multidevice(MDevice *dev)
{
    if (!dev) {
        return;
    }

    uint32_t i;

    free(dev->device);
    free(dev);
}



void do_multidevice(MDevice *dev)
{
    if (!dev) {
        return;
    }

    do_net_crypto(dev->net_crypto);
    do_onion_client(dev->onion_c);

    do_tox_connections(dev->dev_conns);
}

static int get_device_id(MDevice *dev, const uint8_t *real_pk)
{
    uint32_t i;

    for (i = 0; i < dev->device_count; ++i) {
        if (dev->device[i].status > 0) {
            if (id_equal(real_pk, dev->device[i].real_pk)) {
                return i;
            }
        }
    }

    return -1;
}

int mdev_add_new_device_self(Tox *tox, const uint8_t *real_pk)
{
    MDevice *dev = tox->mdev;
    if (!public_key_valid(real_pk)) {
        return -1;
    }

    /* TODO
     *
     * check vs our primary key
     * check vs out DHT key
     * check vs already existing in list
     * check vs other?
     */

    int32_t dev_id = get_device_id(dev, real_pk);

    if (dev_id != -1) {
        if (dev->device[dev_id].status >= FRIEND_CONFIRMED) {
            printf("ID Already exists in list...\n");
            return -1;
        }
    }

    int32_t ret = init_new_device_self(dev, real_pk, MDEV_PENDING);

    return ret;
}

