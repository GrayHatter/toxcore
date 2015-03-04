/* Basic group chats testing
 */

#include "../../toxcore/DHT.h"
#include "../../toxcore/tox.h"
#include "../../toxcore/network.h"
#include "../../toxcore/ping.h"
#include "../../toxcore/util.h"
#include "../../toxcore/group_chats.h"
#include "../../toxcore/Messenger.h"
#include "../misc_tools.c"

#include <stdio.h>
#include <stdlib.h>

#define min(a,b) ((a)>(b)?(b):(a))
#define PEERCOUNT   12


void do_messenger_cycle(Messenger **peers, int peercount)
{
    int j;
    for (j=0; j<peercount; j++)
    {
        do_messenger(peers[j]);
    }
}

void idle_n_secs(int n, Messenger **peers, int peercount)
{
    int i;
    for (i=0; i<n*1000; i+=50) /* msecs */
    {
        do_messenger_cycle(peers, peercount);
        usleep(50000); /* usecs */
    }
}

int main(int argc, char *argv[])
{

    Messenger* tox[PEERCOUNT];

    /* Set ip to IPv6 loopback. TODO: IPv4 fallback? */
    IP localhost;
    ip_init(&localhost, 1);
    localhost.ip6.uint8[15]=1;
    Messenger_Options options = {0};
    options.ipv6enabled = TOX_ENABLE_IPV6_DEFAULT;

    printf("DHT public keys:\n");
    int i;
    for (i=0; i<PEERCOUNT; i++)
    {
        tox[i] = new_messenger(&options);
        char nick[32];
        snprintf(nick, sizeof(nick), "Botik %d", rand());
        setname(tox[i], nick, strlen(nick));
        printf("nick: %s\n", nick);
        printf("%s, %d\n", id_toa(tox[i]->dht->self_public_key), i);
    }

    printf("Bootstrapping from node\n");

    int argvoffset = cmdline_parsefor_ipv46(argc, argv, &options.ipv6enabled);
    uint16_t port = atoi(argv[argvoffset + 2]);
    unsigned char *bnode_dht_key = hex_string_to_bin(argv[argvoffset + 3]);
    printf("%s\n", id_toa(bnode_dht_key));
    printf("%s\n", argv[argvoffset+1]);
    printf("%d\n", port);


    for (i=0; i<PEERCOUNT; i++)
    {
        int res = DHT_bootstrap_from_address(tox[i]->dht, argv[argvoffset+1], options.ipv6enabled, port, bnode_dht_key);
        if (!res)
            printf("Bootstrap failed\n");
    }


    printf("Waiting until every Tox instance is connected\n");
    for (;;)
    {
        do_messenger_cycle(tox, PEERCOUNT);

        int numconnected=0;
        for (i=0;i<PEERCOUNT;i++)
            numconnected+=DHT_isconnected(tox[i]->dht);
       // printf("%d\n", numconnected);

        if (numconnected>PEERCOUNT*min(PEERCOUNT,LCLIENT_LIST))
            break;

        /* TODO: busy wait might be slightly more efficient here */
        usleep(50000);
    }

    idle_n_secs(10, tox, PEERCOUNT);
    printf("Network is connected\n");
    printf("Joining the groupchat\n");
    unsigned char *chatid = hex_string_to_bin(argv[argvoffset + 4]);

    for (i=0; i<PEERCOUNT; i++) {
        do_messenger_cycle(tox, PEERCOUNT);
        int res = gc_group_join(tox[i]->group_handler, chatid);
        idle_n_secs(3, tox, PEERCOUNT);   // comment this out to spam invites as fast as possible

        if (res<0)
            printf("Get nodes request failed\n");
    }

    idle_n_secs(240, tox, PEERCOUNT);

    return 0;
}
