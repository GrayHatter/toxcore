/* tox.c
 *
 * The Tox public API.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "Messenger.h"
#include "logger.h"
#include "group_chats.h"

#include "../toxencryptsave/defines.h"

#define TOX_DEFINED
typedef struct Messenger Tox;

#include "tox.h"

#define SET_ERROR_PARAMETER(param, x) {if(param) {*param = x;}}

#if TOX_HASH_LENGTH != crypto_hash_sha256_BYTES
#error TOX_HASH_LENGTH is assumed to be equal to crypto_hash_sha256_BYTES
#endif

#if FILE_ID_LENGTH != crypto_box_KEYBYTES
#error FILE_ID_LENGTH is assumed to be equal to crypto_box_KEYBYTES
#endif

#if TOX_FILE_ID_LENGTH != crypto_box_KEYBYTES
#error TOX_FILE_ID_LENGTH is assumed to be equal to crypto_box_KEYBYTES
#endif

#if TOX_FILE_ID_LENGTH != TOX_HASH_LENGTH
#error TOX_FILE_ID_LENGTH is assumed to be equal to TOX_HASH_LENGTH
#endif

#if TOX_PUBLIC_KEY_SIZE != crypto_box_PUBLICKEYBYTES
#error TOX_PUBLIC_KEY_SIZE is assumed to be equal to crypto_box_PUBLICKEYBYTES
#endif

#if TOX_SECRET_KEY_SIZE != crypto_box_SECRETKEYBYTES
#error TOX_SECRET_KEY_SIZE is assumed to be equal to crypto_box_SECRETKEYBYTES
#endif

#if TOX_MAX_NAME_LENGTH != MAX_NAME_LENGTH
#error TOX_MAX_NAME_LENGTH is assumed to be equal to MAX_NAME_LENGTH
#endif

#if TOX_MAX_STATUS_MESSAGE_LENGTH != MAX_STATUSMESSAGE_LENGTH
#error TOX_MAX_STATUS_MESSAGE_LENGTH is assumed to be equal to MAX_STATUSMESSAGE_LENGTH
#endif

uint32_t tox_version_major(void)
{
    return 0;
}

uint32_t tox_version_minor(void)
{
    return 0;
}

uint32_t tox_version_patch(void)
{
    return 0;
}

bool tox_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch)
{
    //TODO
    return 1;
}


void tox_options_default(struct Tox_Options *options)
{
    if (options) {
        memset(options, 0, sizeof(struct Tox_Options));
        options->ipv6_enabled = 1;
        options->udp_enabled = 1;
        options->proxy_type = TOX_PROXY_TYPE_NONE;
    }
}

struct Tox_Options *tox_options_new(TOX_ERR_OPTIONS_NEW *error)
{
    struct Tox_Options *options = calloc(sizeof(struct Tox_Options), 1);

    if (options) {
        tox_options_default(options);
        SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_OK);
        return options;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_MALLOC);
    return NULL;
}

void tox_options_free(struct Tox_Options *options)
{
    free(options);
}

Tox *tox_new(const struct Tox_Options *options, const uint8_t *data, size_t length, TOX_ERR_NEW *error)
{
    if (!logger_get_global())
        logger_set_global(logger_new(LOGGER_OUTPUT_FILE, LOGGER_LEVEL, "toxcore"));

    if (data == NULL && length != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_NULL);
        return NULL;
    }

    if (data && length) {
        if (length < TOX_ENC_SAVE_MAGIC_LENGTH) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
            return NULL;
        }

        if (memcmp(data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) == 0) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_ENCRYPTED);
            return NULL;
        }
    }

    Messenger_Options m_options = {0};

    if (options == NULL) {
        m_options.ipv6enabled = TOX_ENABLE_IPV6_DEFAULT;
    } else {
        m_options.ipv6enabled = options->ipv6_enabled;
        m_options.udp_disabled = !options->udp_enabled;
        m_options.port_range[0] = options->start_port;
        m_options.port_range[1] = options->end_port;

        switch (options->proxy_type) {
            case TOX_PROXY_TYPE_HTTP:
                m_options.proxy_info.proxy_type = TCP_PROXY_HTTP;
                break;

            case TOX_PROXY_TYPE_SOCKS5:
                m_options.proxy_info.proxy_type = TCP_PROXY_SOCKS5;
                break;

            case TOX_PROXY_TYPE_NONE:
                m_options.proxy_info.proxy_type = TCP_PROXY_NONE;
                break;

            default:
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_TYPE);
                return NULL;
        }

        if (m_options.proxy_info.proxy_type != TCP_PROXY_NONE) {
            if (options->proxy_port == 0) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_PORT);
                return NULL;
            }

            ip_init(&m_options.proxy_info.ip_port.ip, m_options.ipv6enabled);

            if (m_options.ipv6enabled)
                m_options.proxy_info.ip_port.ip.family = AF_UNSPEC;

            if (!addr_resolve_or_parse_ip(options->proxy_host, &m_options.proxy_info.ip_port.ip, NULL)) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_HOST);
                //TODO: TOX_ERR_NEW_PROXY_NOT_FOUND if domain.
                return NULL;
            }

            m_options.proxy_info.ip_port.port = htons(options->proxy_port);
        }
    }

    unsigned int m_error;
    Messenger *m = new_messenger(&m_options, &m_error);

    /*if (!new_groupchats(m)) {
        kill_messenger(m);

        if (m_error == MESSENGER_ERROR_PORT) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PORT_ALLOC);
        } else {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
        }

        return NULL;
    }
    */
    if (data && length && messenger_load(m, data, length) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_OK);
    }

    return m;
}

void tox_kill(Tox *tox)
{
    Messenger *m = tox;
    //kill_groupchats(m->group_chat_object);
    kill_groupchats(m->group_handler);
    kill_messenger(m);
    logger_kill_global();
}

size_t tox_get_savedata_size(const Tox *tox)
{
    const Messenger *m = tox;
    return messenger_size(m);
}

void tox_get_savedata(const Tox *tox, uint8_t *data)
{
    if (data) {
        const Messenger *m = tox;
        messenger_save(m, data);
    }
}

static int address_to_ip(Messenger *m, const char *address, IP_Port *ip_port, IP_Port *ip_port_v4)
{
    if (!addr_parse_ip(address, &ip_port->ip)) {
        if (m->options.udp_disabled) { /* Disable DNS when udp is disabled. */
            return -1;
        }

        IP *ip_extra = NULL;
        ip_init(&ip_port->ip, m->options.ipv6enabled);

        if (m->options.ipv6enabled && ip_port_v4) {
            /* setup for getting BOTH: an IPv6 AND an IPv4 address */
            ip_port->ip.family = AF_UNSPEC;
            ip_reset(&ip_port_v4->ip);
            ip_extra = &ip_port_v4->ip;
        }

        if (!addr_resolve(address, &ip_port->ip, ip_extra)) {
            return -1;
        }
    }

    return 0;
}

bool tox_bootstrap(Tox *tox, const char *address, uint16_t port, const uint8_t *public_key, TOX_ERR_BOOTSTRAP *error)
{
    if (!address || !public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_NULL);
        return 0;
    }

    Messenger *m = tox;
    bool ret = tox_add_tcp_relay(tox, address, port, public_key, error);

    if (!ret) {
        return 0;
    }

    if (m->options.udp_disabled) {
        return ret;
    } else { /* DHT only works on UDP. */
        if (DHT_bootstrap_from_address(m->dht, address, m->options.ipv6enabled, htons(port), public_key) == 0) {
            SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
            return 0;
        }

        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_OK);
        return 1;
    }
}

bool tox_add_tcp_relay(Tox *tox, const char *address, uint16_t port, const uint8_t *public_key,
                       TOX_ERR_BOOTSTRAP *error)
{
    if (!address || !public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_NULL);
        return 0;
    }

    Messenger *m = tox;
    IP_Port ip_port, ip_port_v4;

    if (port == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_PORT);
        return 0;
    }

    if (address_to_ip(m, address, &ip_port, &ip_port_v4) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
        return 0;
    }

    ip_port.port = htons(port);
    add_tcp_relay(m->net_crypto, ip_port, public_key);
    onion_add_bs_path_node(m->onion_c, ip_port, public_key); //TODO: move this

    SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_OK);
    return 1;
}

TOX_CONNECTION tox_self_get_connection_status(const Tox *tox)
{
    const Messenger *m = tox;

    unsigned int ret = onion_connection_status(m->onion_c);

    if (ret == 2) {
        return TOX_CONNECTION_UDP;
    } else if (ret == 1) {
        return TOX_CONNECTION_TCP;
    } else {
        return TOX_CONNECTION_NONE;
    }
}


void tox_callback_self_connection_status(Tox *tox, tox_self_connection_status_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_core_connection(m, function, user_data);
}

uint32_t tox_iteration_interval(const Tox *tox)
{
    const Messenger *m = tox;
    return messenger_run_interval(m);
}

void tox_iterate(Tox *tox)
{
    Messenger *m = tox;
    do_messenger(m);
    //do_groupchats(m->group_chat_object);
}

void tox_self_get_address(const Tox *tox, uint8_t *address)
{
    if (address) {
        const Messenger *m = tox;
        getaddress(m, address);
    }
}

void tox_self_set_nospam(Tox *tox, uint32_t nospam)
{
    Messenger *m = tox;
    set_nospam(&(m->fr), nospam);
}

uint32_t tox_self_get_nospam(const Tox *tox)
{
    const Messenger *m = tox;
    return get_nospam(&(m->fr));
}

void tox_self_get_public_key(const Tox *tox, uint8_t *public_key)
{
    const Messenger *m = tox;

    if (public_key)
        memcpy(public_key, m->net_crypto->self_public_key, crypto_box_PUBLICKEYBYTES);
}

void tox_self_get_secret_key(const Tox *tox, uint8_t *secret_key)
{
    const Messenger *m = tox;

    if (secret_key)
        memcpy(secret_key, m->net_crypto->self_secret_key, crypto_box_SECRETKEYBYTES);
}

bool tox_self_set_name(Tox *tox, const uint8_t *name, size_t length, TOX_ERR_SET_INFO *error)
{
    if (!name && length != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_NULL);
        return 0;
    }

    Messenger *m = tox;

    if (setname(m, name, length) == 0) {
        //TODO: function to set different per group names?
        //send_name_all_groups(m->group_chat_object);
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_OK);
        return 1;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_TOO_LONG);
        return 0;
    }
}

size_t tox_self_get_name_size(const Tox *tox)
{
    const Messenger *m = tox;
    return m_get_self_name_size(m);
}

void tox_self_get_name(const Tox *tox, uint8_t *name)
{
    if (name) {
        const Messenger *m = tox;
        getself_name(m, name);
    }
}

bool tox_self_set_status_message(Tox *tox, const uint8_t *status, size_t length, TOX_ERR_SET_INFO *error)
{
    if (!status && length != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_NULL);
        return 0;
    }

    Messenger *m = tox;

    if (m_set_statusmessage(m, status, length) == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_OK);
        return 1;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_TOO_LONG);
        return 0;
    }
}

size_t tox_self_get_status_message_size(const Tox *tox)
{
    const Messenger *m = tox;
    return m_get_self_statusmessage_size(m);
}

void tox_self_get_status_message(const Tox *tox, uint8_t *status)
{
    if (status) {
        const Messenger *m = tox;
        m_copy_self_statusmessage(m, status);
    }
}

void tox_self_set_status(Tox *tox, TOX_USER_STATUS user_status)
{
    Messenger *m = tox;
    m_set_userstatus(m, user_status);
}

TOX_USER_STATUS tox_self_get_status(const Tox *tox)
{
    const Messenger *m = tox;
    return m_get_self_userstatus(m);
}

static void set_friend_error(int32_t ret, TOX_ERR_FRIEND_ADD *error)
{
    switch (ret) {
        case FAERR_TOOLONG:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_TOO_LONG);
            break;

        case FAERR_NOMESSAGE:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NO_MESSAGE);
            break;

        case FAERR_OWNKEY:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OWN_KEY);
            break;

        case FAERR_ALREADYSENT:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_ALREADY_SENT);
            break;

        case FAERR_BADCHECKSUM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_BAD_CHECKSUM);
            break;

        case FAERR_SETNEWNOSPAM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM);
            break;

        case FAERR_NOMEM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_MALLOC);
            break;

    }
}

uint32_t tox_friend_add(Tox *tox, const uint8_t *address, const uint8_t *message, size_t length,
                        TOX_ERR_FRIEND_ADD *error)
{
    if (!address || !message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NULL);
        return UINT32_MAX;
    }

    Messenger *m = tox;
    int32_t ret = m_addfriend(m, address, message, length);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OK);
        return ret;
    }

    set_friend_error(ret, error);
    return UINT32_MAX;
}

uint32_t tox_friend_add_norequest(Tox *tox, const uint8_t *public_key, TOX_ERR_FRIEND_ADD *error)
{
    if (!public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NULL);
        return UINT32_MAX;
    }

    Messenger *m = tox;
    int32_t ret = m_addfriend_norequest(m, public_key);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OK);
        return ret;
    }

    set_friend_error(ret, error);
    return UINT32_MAX;
}

bool tox_friend_delete(Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_DELETE *error)
{
    Messenger *m = tox;
    int ret = m_delfriend(m, friend_number);

    //TODO handle if realloc fails?
    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_DELETE_OK);
    return 1;
}

uint32_t tox_friend_by_public_key(const Tox *tox, const uint8_t *public_key, TOX_ERR_FRIEND_BY_PUBLIC_KEY *error)
{
    if (!public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_NULL);
        return UINT32_MAX;
    }

    const Messenger *m = tox;
    int32_t ret = getfriend_id(m, public_key);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK);
    return ret;
}

bool tox_friend_get_public_key(const Tox *tox, uint32_t friend_number, uint8_t *public_key,
                               TOX_ERR_FRIEND_GET_PUBLIC_KEY *error)
{
    if (!public_key) {
        return 0;
    }

    const Messenger *m = tox;

    if (get_real_pk(m, friend_number, public_key) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK);
    return 1;
}

bool tox_friend_exists(const Tox *tox, uint32_t friend_number)
{
    const Messenger *m = tox;
    return m_friend_exists(m, friend_number);
}

uint64_t tox_friend_get_last_online(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_GET_LAST_ONLINE *error)
{
    const Messenger *m = tox;
    uint64_t timestamp = m_get_last_online(m, friend_number);

    if (timestamp == UINT64_MAX) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_LAST_ONLINE_FRIEND_NOT_FOUND)
        return UINT64_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_LAST_ONLINE_OK);
    return timestamp;
}

size_t tox_self_get_friend_list_size(const Tox *tox)
{
    const Messenger *m = tox;
    return count_friendlist(m);
}

void tox_self_get_friend_list(const Tox *tox, uint32_t *list)
{
    if (list) {
        const Messenger *m = tox;
        //TODO: size parameter?
        copy_friendlist(m, list, tox_self_get_friend_list_size(tox));
    }
}

size_t tox_friend_get_name_size(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    const Messenger *m = tox;
    int ret = m_get_name_size(m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return SIZE_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

bool tox_friend_get_name(const Tox *tox, uint32_t friend_number, uint8_t *name, TOX_ERR_FRIEND_QUERY *error)
{
    if (!name) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_NULL);
        return 0;
    }

    const Messenger *m = tox;
    int ret = getname(m, friend_number, name);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return 1;
}

void tox_callback_friend_name(Tox *tox, tox_friend_name_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_namechange(m, function, user_data);
}

size_t tox_friend_get_status_message_size(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    const Messenger *m = tox;
    int ret = m_get_statusmessage_size(m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return SIZE_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

bool tox_friend_get_status_message(const Tox *tox, uint32_t friend_number, uint8_t *message,
                                   TOX_ERR_FRIEND_QUERY *error)
{
    if (!message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_NULL);
        return 0;
    }

    const Messenger *m = tox;
    //TODO: size parameter?
    int ret = m_copy_statusmessage(m, friend_number, message, m_get_statusmessage_size(m, friend_number));

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return 1;
}

void tox_callback_friend_status_message(Tox *tox, tox_friend_status_message_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_statusmessage(m, function, user_data);
}

TOX_USER_STATUS tox_friend_get_status(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    const Messenger *m = tox;

    int ret = m_get_userstatus(m, friend_number);

    if (ret == USERSTATUS_INVALID) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return TOX_USER_STATUS_BUSY + 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

void tox_callback_friend_status(Tox *tox, tox_friend_status_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_userstatus(m, function, user_data);
}

TOX_CONNECTION tox_friend_get_connection_status(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    const Messenger *m = tox;

    int ret = m_get_friend_connectionstatus(m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return TOX_CONNECTION_NONE;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

void tox_callback_friend_connection_status(Tox *tox, tox_friend_connection_status_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_connectionstatus(m, function, user_data);
}

bool tox_friend_get_typing(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    const Messenger *m = tox;
    int ret = m_get_istyping(m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return !!ret;
}

void tox_callback_friend_typing(Tox *tox, tox_friend_typing_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_typingchange(m, function, user_data);
}

bool tox_self_set_typing(Tox *tox, uint32_t friend_number, bool is_typing, TOX_ERR_SET_TYPING *error)
{
    Messenger *m = tox;

    if (m_set_usertyping(m, friend_number, is_typing) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_TYPING_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_SET_TYPING_OK);
    return 1;
}

static void set_message_error(int ret, TOX_ERR_FRIEND_SEND_MESSAGE *error)
{
    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_OK);
            break;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND);
            break;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG);
            break;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED);
            break;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ);
            break;

        case -5:
            /* can't happen */
            break;
    }
}

uint32_t tox_friend_send_message(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message,
                                 size_t length, TOX_ERR_FRIEND_SEND_MESSAGE *error)
{
    if (!message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_NULL);
        return 0;
    }

    if (!length) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY);
        return 0;
    }

    Messenger *m = tox;
    uint32_t message_id = 0;
    set_message_error(m_send_message_generic(m, friend_number, type, message, length, &message_id), error);
    return message_id;
}

void tox_callback_friend_read_receipt(Tox *tox, tox_friend_read_receipt_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_read_receipt(m, function, user_data);
}

void tox_callback_friend_request(Tox *tox, tox_friend_request_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_friendrequest(m, function, user_data);
}

void tox_callback_friend_message(Tox *tox, tox_friend_message_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_friendmessage(m, function, user_data);
}

bool tox_hash(uint8_t *hash, const uint8_t *data, size_t length)
{
    if (!hash || !data) {
        return 0;
    }

    crypto_hash_sha256(hash, data, length);
    return 1;
}

bool tox_file_control(Tox *tox, uint32_t friend_number, uint32_t file_number, TOX_FILE_CONTROL control,
                      TOX_ERR_FILE_CONTROL *error)
{
    Messenger *m = tox;
    int ret = file_control(m, friend_number, file_number, control);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_NOT_FOUND);
            return 0;

        case -4:
            /* can't happen */
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_ALREADY_PAUSED);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_DENIED);
            return 0;

        case -7:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_NOT_PAUSED);
            return 0;

        case -8:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_SENDQ);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_file_seek(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
                   TOX_ERR_FILE_SEEK *error)
{
    Messenger *m = tox;
    int ret = file_seek(m, friend_number, file_number, position);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_NOT_FOUND);
            return 0;

        case -4:
        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_DENIED);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_INVALID_POSITION);
            return 0;

        case -8:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_SENDQ);
            return 0;
    }

    /* can't happen */
    return 0;
}

void tox_callback_file_recv_control(Tox *tox, tox_file_recv_control_cb *function, void *user_data)
{
    Messenger *m = tox;
    callback_file_control(m, function, user_data);
}

bool tox_file_get_file_id(const Tox *tox, uint32_t friend_number, uint32_t file_number, uint8_t *file_id,
                          TOX_ERR_FILE_GET *error)
{
    const Messenger *m = tox;
    int ret = file_get_id(m, friend_number, file_number, file_id);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_OK);
        return 1;
    } else if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_FRIEND_NOT_FOUND);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_NOT_FOUND);
    }

    return 0;
}

uint32_t tox_file_send(Tox *tox, uint32_t friend_number, uint32_t kind, uint64_t file_size, const uint8_t *file_id,
                       const uint8_t *filename, size_t filename_length, TOX_ERR_FILE_SEND *error)
{
    if (filename_length && !filename) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_NULL);
        return UINT32_MAX;
    }

    uint8_t f_id[FILE_ID_LENGTH];

    if (!file_id) {
        /* Tox keys are 32 bytes like FILE_ID_LENGTH. */
        new_symmetric_key(f_id);
        file_id = f_id;
    }

    Messenger *m = tox;
    long int file_num = new_filesender(m, friend_number, kind, file_size, file_id, filename, filename_length);

    if (file_num >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_OK);
        return file_num;
    }

    switch (file_num) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_FRIEND_NOT_FOUND);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_NAME_TOO_LONG);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_TOO_MANY);
            return UINT32_MAX;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_FRIEND_NOT_CONNECTED);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

bool tox_file_send_chunk(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position, const uint8_t *data,
                         size_t length, TOX_ERR_FILE_SEND_CHUNK *error)
{
    Messenger *m = tox;
    int ret = file_data(m, friend_number, file_number, position, data, length);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_NOT_FOUND);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_NOT_TRANSFERRING);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_INVALID_LENGTH);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_SENDQ);
            return 0;

        case -7:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_WRONG_POSITION);
            return 0;
    }

    /* can't happen */
    return 0;
}

void tox_callback_file_chunk_request(Tox *tox, tox_file_chunk_request_cb *function, void *user_data)
{
    Messenger *m = tox;
    callback_file_reqchunk(m, function, user_data);
}

void tox_callback_file_recv(Tox *tox, tox_file_recv_cb *function, void *user_data)
{
    Messenger *m = tox;
    callback_file_sendrequest(m, function, user_data);
}

void tox_callback_file_recv_chunk(Tox *tox, tox_file_recv_chunk_cb *function, void *user_data)
{
    Messenger *m = tox;
    callback_file_data(m, function, user_data);
}

static void set_custom_packet_error(int ret, TOX_ERR_FRIEND_CUSTOM_PACKET *error)
{
    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_OK);
            break;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND);
            break;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG);
            break;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID);
            break;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED);
            break;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ);
            break;
    }
}

bool tox_friend_send_lossy_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                  TOX_ERR_FRIEND_CUSTOM_PACKET *error)
{
    if (!data) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_NULL);
        return 0;
    }

    Messenger *m = tox;

    if (length == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY);
        return 0;
    }

    if (data[0] < (PACKET_ID_LOSSY_RANGE_START + PACKET_LOSSY_AV_RESERVED)) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID);
        return 0;
    }

    int ret = send_custom_lossy_packet(m, friend_number, data, length);

    set_custom_packet_error(ret, error);

    if (ret == 0) {
        return 1;
    } else {
        return 0;
    }
}

void tox_callback_friend_lossy_packet(Tox *tox, tox_friend_lossy_packet_cb *function, void *user_data)
{
    Messenger *m = tox;
    custom_lossy_packet_registerhandler(m, function, user_data);
}

bool tox_friend_send_lossless_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                     TOX_ERR_FRIEND_CUSTOM_PACKET *error)
{
    if (!data) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_NULL);
        return 0;
    }

    Messenger *m = tox;

    if (length == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY);
        return 0;
    }

    int ret = send_custom_lossless_packet(m, friend_number, data, length);

    set_custom_packet_error(ret, error);

    if (ret == 0) {
        return 1;
    } else {
        return 0;
    }
}

void tox_callback_friend_lossless_packet(Tox *tox, tox_friend_lossless_packet_cb *function, void *user_data)
{
    Messenger *m = tox;
    custom_lossless_packet_registerhandler(m, function, user_data);
}

void tox_self_get_dht_id(const Tox *tox, uint8_t *dht_id)
{
    if (dht_id) {
        const Messenger *m = tox;
        memcpy(dht_id , m->dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    }
}

uint16_t tox_self_get_udp_port(const Tox *tox, TOX_ERR_GET_PORT *error)
{
    const Messenger *m = tox;
    uint16_t port = htons(m->net->port);

    if (port) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_OK);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_NOT_BOUND);
    }

    return port;
}

uint16_t tox_self_get_tcp_port(const Tox *tox, TOX_ERR_GET_PORT *error)
{
    /* TCP server not yet implemented in clients. */
    SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_NOT_BOUND);
    return 0;
}

/**************** GROUPCHAT FUNCTIONS *****************/

/* Set the callback for group invites from friends. Length should be TOX_GROUP_INVITE_DATA_SIZE.
 *
 * function(Tox *m, int32_t friendnumber, const uint8_t *invite_data, uint16_t length, void *userdata)
 */
void tox_callback_group_invite(Tox *tox, void (*function)(Tox *m, int32_t, const uint8_t *, uint16_t length, void *),
                               void *userdata)
{
    Messenger *m = tox;
    m_callback_group_invite(m, function, userdata);
}

/* Set the callback for group messages.
 *
 *  function(Tox *m, int groupnumber, uint32_t peernumber, const uint8_t *message, uint16_t length, void *userdata)
 */
void tox_callback_group_message(Tox *tox, void (*function)(Tox *m, int, uint32_t, const uint8_t *, uint16_t,
                                void *), void *userdata)
{
    Messenger *m = tox;
    gc_callback_message(m, function, userdata);
}

/* Set the callback for group private messages.
 *
 *  function(Tox *m, int groupnumber, uint32_t peernumber, const uint8_t *message, uint16_t length, void *userdata)
 */
void tox_callback_group_private_message(Tox *tox, void (*function)(Tox *m, int, uint32_t, const uint8_t *, uint16_t,
                                        void *), void *userdata)
{
    Messenger *m = tox;
    gc_callback_private_message(m, function, userdata);
}

/* Set the callback for group action messages (aka /me messages).
 *
 *  function(Tox *m, int groupnumber, uint32_t peernumber, const uint8_t *message, uint16_t length, void *userdata)
 */
void tox_callback_group_action(Tox *tox, void (*function)(Tox *m, int, uint32_t, const uint8_t *, uint16_t,
                               void *), void *userdata)
{
    Messenger *m = tox;
    gc_callback_action(m, function, userdata);
}

/* Set the callback for group operator certificates.
 *
 *  function(Tox *m, int groupnumber, uint32_t source_peernum, uint32_t target_peernum, uint8_t certificate_type, void *userdata)
 */
void tox_callback_group_op_certificate(Tox *tox, void (*function)(Tox *m, int, uint32_t, uint32_t, uint8_t, void *),
                                       void *userdata)
{
    Messenger *m = tox;
    gc_callback_op_certificate(m, function, userdata);
}

/* Set the callback for group peer nickname changes.
 *
 * function(Tox *m, int groupnumber, uint32_t peernumber, const uint8_t *newnick, uint32_t length, void *userdata)
 */
void tox_callback_group_nick_change(Tox *tox, void (*function)(Tox *m, int, uint32_t, const uint8_t *, uint16_t,
                                    void *), void *userdata)
{
    Messenger *m = tox;
    gc_callback_nick_change(m, function, userdata);
}

/* Set the callback for group peer status changes.
 *
 * function(Tox *m, int groupnumber, uint32_t peernumber, uint8_t status, void *userdata)
 */
void tox_callback_group_status_change(Tox *tox, void (*function)(Tox *m, int, uint32_t, uint8_t, void *), void *userdata)
{
    Messenger *m = tox;
    gc_callback_status_change(m, function, userdata);
}

/* Set the callback for group topic changes.
 *
 * function(Tox *m, int groupnumber, uint32_t peernumber, const uint8_t *topic, uint16_t length, void *userdata)
 */
void tox_callback_group_topic_change(Tox *tox, void (*function)(Tox *m, int, uint32_t, const uint8_t *,
                                     uint16_t, void *), void *userdata)
{
    Messenger *m = tox;
    gc_callback_topic_change(m, function, userdata);
}

/* Set the callback for group peer join. This callback must not be
 * relied on for updating the client's peer list (use tox_callback_group_peerlist_update).
 *
 * function(Tox *m, int groupnumber, uint32_t peernumber, void *userdata)
 */
void tox_callback_group_peer_join(Tox *tox, void (*function)(Tox *m, int, uint32_t, void *), void *userdata)
{
    Messenger *m = tox;
    gc_callback_peer_join(m, function, userdata);
}

/* Set the callback for group peer exit alert. This callback must not be
 * relied on for updating the client's peer list (use tox_callback_group_peerlist_update).
 *
 *
 * function(Tox *m, int groupnumber, uint32_t peernumber, const uint8_t *partmessage, uint16_t length, void *userdata)
 */
void tox_callback_group_peer_exit(Tox *tox, void (*function)(Tox *m, int, uint32_t, const uint8_t *, uint16_t,
                                  void *), void *userdata)
{
    Messenger *m = tox;
    gc_callback_peer_exit(m, function, userdata);
}

/* Set the callback for group self join.
 *
 * function(Tox *m, int groupnumber, void *userdata)
 */
void tox_callback_group_self_join(Tox *tox, void (*function)(Tox *m, int, void *), void *userdata)
{
    Messenger *m = tox;
    gc_callback_self_join(m, function, userdata);
}

/* Set the callback for peerlist update. Should be used with tox_group_get_names.
 *
 * function(Tox *m, int groupnumber, void *userdata)
 */
void tox_callback_group_peerlist_update(Tox *tox, void (*function)(Tox *m, int, void *), void *userdata)
{
    Messenger *m = tox;
    gc_callback_peerlist_update(m, function, userdata);
}

/* Set the callback for self timeout.
 *
 * function(Tox *m, int groupnumber, void *userdata)
 */
void tox_callback_group_self_timeout(Tox *tox, void (*function)(Tox *m, int, void *), void *userdata)
{
    Messenger *m = tox;
    gc_callback_self_timeout(m, function, userdata);
}

/* Set the callback for when your join attempt is rejected where type is one of TOX_GROUP_JOIN_REJECTED.
 *
 * function(Tox *m, int groupnumber, uint8_t type, void *userdata)
 */
void tox_callback_group_rejected(Tox *tox, void (*function)(Tox *m, int, uint8_t, void *), void *userdata)
{
    Messenger *m = tox;
    gc_callback_rejected(m, function, userdata);
}

/* Adds a new groupchat to group chats array.
 * group_name is required and length must not exceed TOX_MAX_GROUP_NAME_LENGTH bytes.
 *
 * Return groupnumber on success.
 * Return -1 on failure.
 */
int tox_group_new(Tox *tox, const uint8_t *group_name, uint16_t length)
{
    Messenger *m = tox;
    return gc_group_add(m->group_handler, group_name, length);
}

/* Joins a groupchat using the supplied chat_id
 *
 * Return groupnumber on success.
 * Return -1 on failure.
 */
int tox_group_new_join(Tox *tox, const uint8_t *chat_id)
{
    Messenger *m = tox;
    return gc_group_join(m->group_handler, chat_id);
}

/* Reconnects to groupnumber's group and maintains your own state, i.e. status, keys, certificates
 *
 * Return 0 on success.
 * Return -1 on failure or if already connected to the group.
 */
int tox_group_reconnect(Tox *tox, int groupnumber)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    gc_rejoin_group(m->group_handler, chat);
    return 0;
}

/* Joins a group using the invite data received in a friend's group invite.
 * Length should be TOX_GROUP_INVITE_DATA_SIZE.
 *
 * Return groupnumber on success.
 * Return -1 on failure
 */
int tox_group_accept_invite(Tox *tox, const uint8_t *invite_data, uint16_t length)
{
    Messenger *m = tox;
    return gc_accept_invite(m->group_handler, invite_data, length);
}

/* Invites friendnumber to groupnumber.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int tox_group_invite_friend(Tox *tox, int groupnumber, int32_t friendnumber)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_invite_friend(m->group_handler, chat, friendnumber);
}

/* Deletes groupnumber's group chat and sends an optional parting message to group peers
 * The maximum parting message length is TOX_MAX_GROUP_PART_LENGTH.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int tox_group_delete(Tox *tox, int groupnumber, const uint8_t *partmessage, uint16_t length)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_group_exit(m->group_handler, chat, partmessage, length);
}

/* Sends a groupchat message to groupnumber. Messages should be split at TOX_MAX_MESSAGE_LENGTH bytes.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int tox_group_message_send(const Tox *tox, int groupnumber, const uint8_t *message, uint16_t length)
{
    const Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_send_message(chat, message, length, GM_PLAIN_MESSAGE);
}

/* Sends a private message to peernumber in groupnumber. Messages should be split at TOX_MAX_MESSAGE_LENGTH bytes.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int tox_group_private_message_send(const Tox *tox, int groupnumber, uint32_t peernumber, const uint8_t *message,
                                   uint16_t length)
{
    const Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_send_private_message(chat, peernumber, message, length);
}

/* Sends a groupchat action message to groupnumber. Messages should be split at TOX_MAX_MESSAGE_LENGTH bytes.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int tox_group_action_send(const Tox *tox, int groupnumber, const uint8_t *message, uint16_t length)
{
    const Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_send_message(chat, message, length, GM_ACTION_MESSAGE);
}

/* Issues a groupchat operator certificate for peernumber to groupnumber.
 * type must be a TOX_GROUP_OP_CERTIFICATE.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int tox_group_op_certificate_send(const Tox *tox, int groupnumber, uint32_t peernumber, uint8_t type)
{
    const Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_send_op_certificate(chat, peernumber, type);
}

/* Sets your name for groupnumber. length should be no larger than TOX_MAX_NAME_LENGTH bytes.
 *
 * Return 0 on success.
 * Return -1 on failure.
 * Return -2 if nick is already taken by another group member
 */
int tox_group_set_self_name(Tox *tox, int groupnumber, const uint8_t *name, uint16_t length)
{
    Messenger *m = tox;
    return gc_set_self_nick(m, groupnumber, name, length);
}

/* Get peernumber's name in groupnumber's group chat.
 * name buffer must be at least TOX_MAX_NAME_LENGTH bytes.
 *
 * Return length of name on success.
 * Reutrn -1 on failure.
 */
int tox_group_get_peer_name(const Tox *tox, int groupnumber, uint32_t peernumber, uint8_t *name)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_get_peer_nick(chat, peernumber, name);
}

/* Get peernumber's name's size in bytes in groupnumber's group chat.
 *
 * Return length of name on success.
 * Reutrn -1 on failure.
 */
int tox_group_get_peer_name_size(const Tox *tox, int groupnumber, uint32_t peernumber)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_get_peer_nick_size(chat, peernumber);
}

/* Get your own name for groupnumber's group.
 * name buffer must be at least TOX_MAX_NAME_LENGTH bytes.
 *
 * Return length of name on success.
 * Return -1 on failure.
 */
int tox_group_get_self_name(const Tox *tox, int groupnumber, uint8_t *name)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_get_self_nick(chat, name);
}

/* Get your own name's size in bytes for groupnumber's group.
 *
 * Return length of name on success.
 * Return -1 on failure.
 */
int tox_group_get_self_name_size(const Tox *tox, int groupnumber)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_get_self_nick_size(chat);
}

/* Sets groupnumber's topic.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int tox_group_set_topic(Tox *tox, int groupnumber, const uint8_t *topic, uint16_t length)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_set_topic(chat, topic, length);
}

/* Gets groupnumber's topic. topic buffer must be at least TOX_MAX_GROUP_TOPIC_LENGTH bytes.
 *
 * Return topic length on success.
 * Return -1 on failure.
 */
int tox_group_get_topic(const Tox *tox, int groupnumber, uint8_t *topic)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_get_topic(chat, topic);
}

/* Gets groupnumber's topic's size in bytes.
 *
 * Return topic length on success.
 * Return -1 on failure.
 */
int tox_group_get_topic_size(const Tox *tox, int groupnumber)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_get_topic_size(chat);
}

/* Gets groupnumber's group name. groupname buffer must be at least TOX_MAX_GROUP_NAME_LENGTH bytes.
 *
 * Return group name's length on success.
 * Return -1 on failure.
 */
 int tox_group_get_group_name(const Tox *tox, int groupnumber, uint8_t *groupname)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_get_group_name(chat, groupname);
}

/* Gets groupnumber's group name's size in bytes.
 *
 * Return group name's length on success.
 * Return -1 on failure.
 */
 int tox_group_get_group_name_size(const Tox *tox, int groupnumber)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_get_group_name_size(chat);
}

/* Sets your status for groupnumber.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int tox_group_set_status(Tox *tox, int groupnumber, uint8_t status_type)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_set_self_status(chat, status_type);
}

/* Get peernumber's status in groupnumber's group chat.
 *
 * Returns a TOX_GROUP_STATUS on success.
 * Returns TOX_GS_INVALID on failure.
 */
uint8_t tox_group_get_status(const Tox *tox, int groupnumber, uint32_t peernumber)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return TOX_GS_INVALID;

    return gc_get_status(chat, peernumber);
}

/* Get your own group status in groupnumber's group chat.
 *
 * Returns a TOX_GROUP_STATUS on success.
 * Returns TOX_GS_INVALID on failure.
 */
uint8_t tox_group_get_self_status(const Tox *tox, int groupnumber)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return TOX_GS_INVALID;

    return gc_get_self_status(chat);
}

/* Get peernumber's group role in groupnumber's group chat.
 *
 * Returns a TOX_GROUP_ROLE on success.
 * Returns TOX_GR_INVALID on failure.
 */
uint8_t tox_group_get_role(const Tox *tox, int groupnumber, uint32_t peernumber)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return TOX_GR_INVALID;

    return gc_get_role(chat, peernumber);
}

/* Get your own group role in groupnumber's group chat.
 *
 * Return a TOX_GROUP_ROLE on success.
 * Return TOX_GR_INVALID on failure.
 */
uint8_t tox_group_get_self_role(const Tox *tox, int groupnumber)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return TOX_GR_INVALID;

    return gc_get_self_role(chat);
}

/* Get invite key (chat_id) for groupnumber's groupchat.
 * The result is stored in 'dest' which must have space for TOX_GROUP_CHAT_ID_SIZE bytes.
 *
 * Returns 0 on success
 * Retruns -1 on failure
 */
int tox_group_get_chat_id(const Tox *tox, int groupnumber, uint8_t *dest)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    gc_get_chat_id(chat, dest);
    return 0;
}

/* Copies the nicks of the peers in groupnumber to the nicks array.
 * Copies the lengths of the nicks to the lengths array.
 *
 * Arrays must have room for num_peers items.
 *
 * Should be used with tox_callback_group_peerlist_update.
 *
 * returns number of peers on success.
 * return -1 on failure.
 */
int tox_group_get_names(const Tox *tox, int groupnumber, uint8_t nicks[][TOX_MAX_NAME_LENGTH], uint16_t lengths[],
                        uint32_t num_peers)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_get_peernames(chat, nicks, lengths, num_peers);
}

/* Returns the number of peers in groupnumber on success.
 * Returns -1 on failure.
 */
int tox_group_get_number_peers(const Tox *tox, int groupnumber)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_get_numpeers(chat);
}

/* Returns the number of active groups. */
uint32_t tox_group_count_groups(const Tox *tox)
{
    const Messenger *m = tox;
    return gc_count_groups(m->group_handler);
}

/* Toggle ignore on peernumber in groupnumber.
 * If ignore is 1, group and private messages from peernumber are ignored, as well as A/V.
 * If ignore is 0, peer is unignored.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int tox_group_toggle_ignore(Tox *tox, int groupnumber, uint32_t peernumber, uint8_t ignore)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL)
        return -1;

    return gc_toggle_ignore(chat, peernumber, ignore);
}
