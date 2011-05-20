/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "config.h"
#include "memcached.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <limits.h>
#include <sysexits.h>
#include <stddef.h>
#include <syslog.h>

#include "sflow_mc.h"

#include "sflow_api.h"
#define SFMC_VERSION "0.91"
#define SFMC_DEFAULT_CONFIGFILE "/etc/hsflowd.auto"
#define SFMC_SEPARATORS " \t\r\n="
/* SFMC_MAX LINE LEN must be enough to hold the whole list of targets */
#define SFMC_MAX_LINELEN 1024
#define SFMC_MAX_COLLECTORS 10

typedef struct _SFMCCollector {
    struct sockaddr sa;
    SFLAddress addr;
    uint16_t port;
    uint16_t priority;
} SFMCCollector;

typedef struct _SFMCConfig {
    int error;
    uint32_t sampling_n;
    uint32_t polling_secs;
    SFLAddress agentIP;
    uint32_t num_collectors;
    SFMCCollector collectors[SFMC_MAX_COLLECTORS];
} SFMCConfig;

typedef struct _SFMC {
    /* sampling parameters */
    uint32_t sflow_random_seed;
    uint32_t sflow_random_threshold;
    /* the sFlow agent */
    SFLAgent *agent;
    /* need mutex when building sample */
    pthread_mutex_t *mutex;
    /* time */
    struct timeval start_time;
    rel_time_t tick;
    /* config */
    char *configFile;
    time_t configFile_modTime;
    SFMCConfig *config;
    uint32_t configTests;
    /* UDP send sockets */
    int socket4;
    int socket6;
} SFMC;

#define SFMC_ATOMIC_FETCH_ADD(_c, _inc) __sync_fetch_and_add(&(_c), (_inc))
#define SFMC_ATOMIC_INC(_c) SFMC_ATOMIC_FETCH_ADD((_c), 1)
#define SFMC_ATOMIC_DEC(_c) SFMC_ATOMIC_FETCH_ADD((_c), -1)

#define SFLOW_DURATION_UNKNOWN 0

/* file-scoped globals */
static SFMC sfmc;

static void sflow_init(SFMC *sm);
  
static void *sfmc_calloc(size_t bytes)
{
    void *mem = calloc(1, bytes);
    if(mem == NULL) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL, "calloc() failed : %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return mem;
}

static  bool lockOrDie(pthread_mutex_t *sem) {
    if(sem && pthread_mutex_lock(sem) != 0) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL, "failed to lock semaphore!");
        exit(EXIT_FAILURE);
    }
    return true;
}

static bool releaseOrDie(pthread_mutex_t *sem) {
    if(sem && pthread_mutex_unlock(sem) != 0) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL, "failed to unlock semaphore!");
        exit(EXIT_FAILURE);
    }
    return true;
}

#define DYNAMIC_LOCAL(VAR) VAR
#define SEMLOCK_DO(_sem) for(int DYNAMIC_LOCAL(_ctrl)=1; DYNAMIC_LOCAL(_ctrl) && lockOrDie(_sem); DYNAMIC_LOCAL(_ctrl)=0, releaseOrDie(_sem))

static void *sfmc_cb_alloc(void *magic, SFLAgent *agent, size_t bytes)
{
    return sfmc_calloc(bytes);
}

static int sfmc_cb_free(void *magic, SFLAgent *agent, void *obj)
{
    free(obj);
    return 0;
}

static void sfmc_cb_error(void *magic, SFLAgent *agent, char *msg)
{
    settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL, "sflow agent error: %s", msg);
}

// copied from memcached.c
static void aggregate_callback(void *in, void *out) {
    struct thread_stats *out_thread_stats = out;
    struct independent_stats *in_independent_stats = in;
    threadlocal_stats_aggregate(in_independent_stats->thread_stats,
                                out_thread_stats);
}

static void sfmc_cb_counters(void *magic, SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    SFMC *sm = (SFMC *)poller->magic;
        
    if(sm->config == NULL ||
       sm->config->polling_secs == 0) {
        /* not configured */
        return;
    }

    SFLCounters_sample_element mcElem = { 0 };
    mcElem.tag = SFLCOUNTERS_MEMCACHE;

    struct thread_stats thread_stats;
    memset(&thread_stats, 0, sizeof(thread_stats));
    if(settings.engine.v1->aggregate_stats != NULL) {
        settings.engine.v1->aggregate_stats(settings.engine.v0,
                                            NULL,
                                            aggregate_callback,
                                            &thread_stats);
    }
    else if (settings.engine.v1->get_stats_struct != NULL) {
        struct independent_stats *independent_stats = settings.engine.v1->get_stats_struct(settings.engine.v0, NULL);
        threadlocal_stats_aggregate(independent_stats->thread_stats, &thread_stats);
    }
    else if(settings.engine.v1->get_stats != NULL) {
        // this one seems to return ASCII - not ideal
        // TODO: implement the .get_stats_struct method for the default engine
    }
    else {
        // default_independent_stats not exported from memcached.c
    }

    // aggregate all the slab stats together
    struct slab_stats slab_stats;
    slab_stats_aggregate(&thread_stats, &slab_stats);
    
#ifndef WIN32
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
#endif /* !WIN32 */

    mcElem.counterBlock.memcache.uptime = sm->tick;

#ifdef WIN32
    mcElem.counterBlock.memcache.rusage_user = 0xFFFFFFFF;
    mcElem.counterBlock.memcache.rusage_system = 0xFFFFFFFF;
#else
    mcElem.counterBlock.memcache.rusage_user = (usage.ru_utime.tv_sec * 1000) + (usage.ru_utime.tv_usec / 1000);
    mcElem.counterBlock.memcache.rusage_system = (usage.ru_stime.tv_sec * 1000) + (usage.ru_stime.tv_usec / 1000);
#endif /* WIN32 */

    mcElem.counterBlock.memcache.curr_connections = stats.curr_conns - 1;
    mcElem.counterBlock.memcache.total_connections = stats.total_conns;
    mcElem.counterBlock.memcache.connection_structures = stats.conn_structs;
    mcElem.counterBlock.memcache.cmd_get = thread_stats.cmd_get;
    mcElem.counterBlock.memcache.cmd_set = slab_stats.cmd_set;
    mcElem.counterBlock.memcache.cmd_flush = thread_stats.cmd_flush;
    mcElem.counterBlock.memcache.get_hits = slab_stats.get_hits;
    mcElem.counterBlock.memcache.get_misses = thread_stats.get_misses;
    mcElem.counterBlock.memcache.delete_misses = thread_stats.delete_misses;
    mcElem.counterBlock.memcache.delete_hits = slab_stats.delete_hits;
    mcElem.counterBlock.memcache.incr_misses = thread_stats.incr_misses;
    mcElem.counterBlock.memcache.incr_hits = thread_stats.incr_hits;
    mcElem.counterBlock.memcache.decr_misses = thread_stats.decr_misses;
    mcElem.counterBlock.memcache.decr_hits = thread_stats.decr_hits;
    mcElem.counterBlock.memcache.cas_misses = thread_stats.cas_misses;
    mcElem.counterBlock.memcache.cas_hits = slab_stats.cas_hits;
    mcElem.counterBlock.memcache.cas_badval = slab_stats.cas_badval;
    mcElem.counterBlock.memcache.auth_cmds = thread_stats.auth_cmds;
    mcElem.counterBlock.memcache.auth_errors = thread_stats.auth_errors;
    mcElem.counterBlock.memcache.bytes_read = thread_stats.bytes_read;
    mcElem.counterBlock.memcache.bytes_written = thread_stats.bytes_written;
    mcElem.counterBlock.memcache.limit_maxbytes = settings.maxbytes;
    // mcElem.counterBlock.memcache.accepting_conns = is_listen_disabled() ? 0 : 1; // $$$ static fn in memcached.c 
    // mcElem.counterBlock.memcache.listen_disabled_num = get_listen_disabled_num(); // $$$ static fn in memcached.c
    mcElem.counterBlock.memcache.threads = settings.num_threads;
    mcElem.counterBlock.memcache.conn_yields = thread_stats.conn_yields;
    SFLADD_ELEMENT(cs, &mcElem);
    SEMLOCK_DO(sm->mutex) {
        sfl_poller_writeCountersSample(poller, cs);
    }
}

static SFLMemcache_prot sflow_map_protocol(enum protocol prot) {
    SFLMemcache_prot sflprot = SFMC_PROT_OTHER;
    switch(prot) {
    case ascii_prot: sflprot = SFMC_PROT_ASCII; break;
    case binary_prot: sflprot = SFMC_PROT_BINARY; break;
    case negotiating_prot:
    default: break;
    }
    return sflprot;
}

static SFLMemcache_operation_status sflow_map_status(int ret) {
    SFLMemcache_operation_status sflret = SFMC_OP_UNKNOWN;
    switch(ret) {
    case ENGINE_NOT_STORED: sflret = SFMC_OP_NOT_STORED; break;
    case ENGINE_SUCCESS: sflret = SFMC_OP_STORED; break;
    case ENGINE_KEY_EEXISTS: sflret = SFMC_OP_EXISTS; break;
    case ENGINE_KEY_ENOENT: sflret = SFMC_OP_NOT_FOUND; break;
    }
    return sflret;
}

static SFLMemcache_cmd sflow_map_ascii_op(int op) {
    SFLMemcache_cmd sflcmd = SFMC_CMD_OTHER;
    switch(op) {
    case OPERATION_ADD: sflcmd=SFMC_CMD_ADD; break;
    case OPERATION_REPLACE: sflcmd = SFMC_CMD_REPLACE; break;
    case OPERATION_APPEND: sflcmd = SFMC_CMD_APPEND; break;
    case OPERATION_PREPEND: sflcmd = SFMC_CMD_PREPEND; break;
    case OPERATION_SET: sflcmd = SFMC_CMD_SET; break;
    case OPERATION_CAS: sflcmd = SFMC_CMD_CAS; break;
        /*            SFMC_CMD_GET */
        /*             SFMC_CMD_GETS */
        /*             SFMC_CMD_INCR */
        /*             SFMC_CMD_DECR */
        /*             SFMC_CMD_DELETE */
        /*             SFMC_CMD_STATS */
        /*             SFMC_CMD_FLUSH */
        /*             SFMC_CMD_VERSION */
        /*             SFMC_CMD_QUIT */
    default:
        break;
    }
    return sflcmd;
}

static SFLMemcache_cmd sflow_map_binary_cmd(int cmd) {
    SFLMemcache_cmd sflcmd = SFMC_CMD_OTHER;
    switch(cmd) {
    case PROTOCOL_BINARY_CMD_GET: sflcmd = SFMC_CMD_GET; break;
    case PROTOCOL_BINARY_CMD_SET: sflcmd = SFMC_CMD_SET; break;
    case PROTOCOL_BINARY_CMD_ADD: sflcmd = SFMC_CMD_ADD; break;
    case PROTOCOL_BINARY_CMD_REPLACE: sflcmd = SFMC_CMD_REPLACE; break;
    case PROTOCOL_BINARY_CMD_DELETE: sflcmd = SFMC_CMD_DELETE; break;
    case PROTOCOL_BINARY_CMD_INCREMENT: sflcmd = SFMC_CMD_INCR; break;
    case PROTOCOL_BINARY_CMD_DECREMENT: sflcmd = SFMC_CMD_DECR; break;
    case PROTOCOL_BINARY_CMD_QUIT: sflcmd = SFMC_CMD_QUIT; break;
    case PROTOCOL_BINARY_CMD_FLUSH: sflcmd = SFMC_CMD_FLUSH; break;
    case PROTOCOL_BINARY_CMD_GETQ: break;
    case PROTOCOL_BINARY_CMD_NOOP: break;
    case PROTOCOL_BINARY_CMD_VERSION: sflcmd = SFMC_CMD_VERSION; break;
    case PROTOCOL_BINARY_CMD_GETK: break;
    case PROTOCOL_BINARY_CMD_GETKQ: break;
    case PROTOCOL_BINARY_CMD_APPEND: sflcmd = SFMC_CMD_APPEND; break;
    case PROTOCOL_BINARY_CMD_PREPEND: sflcmd = SFMC_CMD_PREPEND; break;
    case PROTOCOL_BINARY_CMD_STAT: sflcmd = SFMC_CMD_STATS; break;
    case PROTOCOL_BINARY_CMD_SETQ: break;
    case PROTOCOL_BINARY_CMD_ADDQ: break;
    case PROTOCOL_BINARY_CMD_REPLACEQ: break;
    case PROTOCOL_BINARY_CMD_DELETEQ: break;
    case PROTOCOL_BINARY_CMD_INCREMENTQ: break;
    case PROTOCOL_BINARY_CMD_DECREMENTQ: break;
    case PROTOCOL_BINARY_CMD_QUITQ: break;
    case PROTOCOL_BINARY_CMD_FLUSHQ: break;
    case PROTOCOL_BINARY_CMD_APPENDQ: break;
    case PROTOCOL_BINARY_CMD_PREPENDQ: break;
    case PROTOCOL_BINARY_CMD_VERBOSITY: break;
    case PROTOCOL_BINARY_CMD_TOUCH: break;
    case PROTOCOL_BINARY_CMD_GAT: break;
    case PROTOCOL_BINARY_CMD_GATQ: break;
    case PROTOCOL_BINARY_CMD_SASL_LIST_MECHS: break;
    case PROTOCOL_BINARY_CMD_SASL_AUTH: break;
    case PROTOCOL_BINARY_CMD_SASL_STEP: break;
    default:
        break;
    }
    return sflcmd;
}

/* This is the 32-bit PRNG recommended in G. Marsaglia, "Xorshift RNGs",
 * _Journal of Statistical Software_ 8:14 (July 2003).  According to the paper,
 * it has a period of 2**32 - 1 and passes almost all tests of randomness.  It
 * is currently also used for sFlow sampling in the Open vSwitch project
 * at http://www.openvswitch.org.
 */
void sflow_sample_test(struct conn *c) {
    if(unlikely(!sfmc.sflow_random_seed)) {
        /* sampling not configured */
        return;
    }
    c->thread->sflow_sample_pool++;
    uint32_t seed = c->thread->sflow_random;
    if(unlikely(seed == 0)) {
        /* initialize random number generation */
        seed = sfmc.sflow_random_seed ^ c->thread->index;
    }
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    c->thread->sflow_random = seed;
    if(unlikely(seed <= sfmc.sflow_random_threshold)) {
        /* Relax. We are out of the critical path now. */
        /* since we are sampling at the start of the transaction
           all we have to do here is record the wall-clock time.
           The rest is done at the end of the transaction.
           We could use clock_gettime(CLOCK_REALTIME) here to get
           nanosecond resolution but it is not always implemented
           as efficiently as gettimeofday and it's not clear that
           that we can really do better than microsecond accuracy
           anyway. */
        gettimeofday(&c->sflow_start_time, NULL);
    }
}
        
void sflow_sample(SFLMemcache_cmd command, struct conn *c, const void *key, size_t keylen, uint32_t nkeys, size_t value_bytes, int status)
{
    SFMC *sm = &sfmc;
    if(sm->config == NULL ||
       sm->config->sampling_n == 0 ||
       sm->agent == NULL ||
       sm->agent->samplers == NULL) {
        /* sFlow not configured yet - may be waiting for DNS-SD request */
        return;
    }
    SFLSampler *sampler = sm->agent->samplers;
    struct timeval timenow,elapsed;
    gettimeofday(&timenow, NULL);
    timersub(&timenow, &c->sflow_start_time, &elapsed);
    timerclear(&c->sflow_start_time);
    
    SFL_FLOW_SAMPLE_TYPE fs = { 0 };

    /* have to add up the pool from all the threads */
    fs.sample_pool = sflow_sample_pool_aggregate();
    
    /* indicate that I am the server by setting the
       destination interface to 0x3FFFFFFF=="internal"
       and leaving the source interface as 0=="unknown" */
    fs.output = 0x3FFFFFFF;
            
    SFLFlow_sample_element mcopElem = { 0 };
    mcopElem.tag = SFLFLOW_MEMCACHE;
    mcopElem.flowType.memcache.protocol = sflow_map_protocol(c->protocol);

    // sometimes we pass the command in explicitly
    // otherwise we allow it to be inferred
    if(command == SFMC_CMD_OTHER) {
        if(c->protocol == binary_prot) {
            /* binary protocol has c->cmd */
            command = sflow_map_binary_cmd(c->cmd);
        }
        else {
            /* ascii protocol - infer cmd from the store_op */
            command = sflow_map_ascii_op(c->store_op);
        }
    }
    mcopElem.flowType.memcache.command = command;

    mcopElem.flowType.memcache.key.str = (char *)key;
    mcopElem.flowType.memcache.key.len = (key ? keylen : 0);
    mcopElem.flowType.memcache.nkeys = (nkeys == 0) ? 1 : nkeys;
    mcopElem.flowType.memcache.value_bytes = value_bytes;
    mcopElem.flowType.memcache.duration_uS = (elapsed.tv_sec * 1000000) + elapsed.tv_usec;
    mcopElem.flowType.memcache.status = sflow_map_status(status);
    SFLADD_ELEMENT(&fs, &mcopElem);
    
    SFLFlow_sample_element socElem = { 0 };
    
    if(c->transport == tcp_transport ||
       c->transport == udp_transport) {
        /* add a socket structure */
        struct sockaddr_storage localsoc;
        socklen_t localsoclen = sizeof(localsoc);
        struct sockaddr_storage peersoc;
        socklen_t peersoclen = sizeof(peersoc);
        
        /* ask the fd for the local socket - may have wildcards, but
           at least we may learn the local port */
        getsockname(c->sfd, (struct sockaddr *)&localsoc, &localsoclen);
        /* for tcp the socket can tell us the peer info */
        if(c->transport == tcp_transport) {
            getpeername(c->sfd, (struct sockaddr *)&peersoc, &peersoclen);
        }
        else {
            /* for UDP the peer can be different for every packet, but
               this info is capture in the recvfrom() and given to us */
            memcpy(&peersoc, &c->request_addr, c->request_addr_size);
        }
        
        /* two possibilities here... */
        struct sockaddr_in *soc4 = (struct sockaddr_in *)&peersoc;
        struct sockaddr_in6 *soc6 = (struct sockaddr_in6 *)&peersoc;
        
        if(peersoclen == sizeof(*soc4) && soc4->sin_family == AF_INET) {
            struct sockaddr_in *lsoc4 = (struct sockaddr_in *)&localsoc;
            socElem.tag = SFLFLOW_EX_SOCKET4;
            socElem.flowType.socket4.protocol = (c->transport == tcp_transport ? 6 : 17);
            socElem.flowType.socket4.local_ip.addr = lsoc4->sin_addr.s_addr;
            socElem.flowType.socket4.remote_ip.addr = soc4->sin_addr.s_addr;
            socElem.flowType.socket4.local_port = ntohs(lsoc4->sin_port);
            socElem.flowType.socket4.remote_port = ntohs(soc4->sin_port);
        }
        else if(peersoclen == sizeof(*soc6) && soc6->sin6_family == AF_INET6) {
            struct sockaddr_in6 *lsoc6 = (struct sockaddr_in6 *)&localsoc;
            socElem.tag = SFLFLOW_EX_SOCKET6;
            socElem.flowType.socket6.protocol = (c->transport == tcp_transport ? 6 : 17);
            memcpy(socElem.flowType.socket6.local_ip.addr, lsoc6->sin6_addr.s6_addr, 16);
            memcpy(socElem.flowType.socket6.remote_ip.addr, soc6->sin6_addr.s6_addr, 16);
            socElem.flowType.socket6.local_port = ntohs(lsoc6->sin6_port);
            socElem.flowType.socket6.remote_port = ntohs(soc6->sin6_port);
        }
        if(socElem.tag) {
            SFLADD_ELEMENT(&fs, &socElem);
        }
        else {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, c, "unexpected socket length or address family");
        }
    }
    
    SEMLOCK_DO(sm->mutex) {
        sfl_sampler_writeFlowSample(sampler, &fs);
    }
}


static void sfmc_cb_sendPkt(void *magic, SFLAgent *agent, SFLReceiver *receiver, u_char *pkt, uint32_t pktLen)
{
    SFMC *sm = (SFMC *)magic;
    size_t socklen = 0;
    int fd = 0;
    
    if(sm->config == NULL) {
        /* config is disabled */
        return;
    }

    for(int c = 0; c < sm->config->num_collectors; c++) {
        SFMCCollector *coll = &sm->config->collectors[c];
        switch(coll->addr.type) {
        case SFLADDRESSTYPE_UNDEFINED:
            /* skip over it if the forward lookup failed */
            break;
        case SFLADDRESSTYPE_IP_V4:
            {
                struct sockaddr_in *sa = (struct sockaddr_in *)&(coll->sa);
                socklen = sizeof(struct sockaddr_in);
                sa->sin_family = AF_INET;
                sa->sin_port = htons(coll->port);
                fd = sm->socket4;
            }
            break;
        case SFLADDRESSTYPE_IP_V6:
            {
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&(coll->sa);
                socklen = sizeof(struct sockaddr_in6);
                sa6->sin6_family = AF_INET6;
                sa6->sin6_port = htons(coll->port);
                fd = sm->socket6;
            }
            break;
        }
        
        if(socklen && fd > 0) {
            int result = sendto(fd,
                                pkt,
                                pktLen,
                                0,
                                (struct sockaddr *)&coll->sa,
                                socklen);
            if(result == -1 && errno != EINTR) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL, "socket sendto error: %s", strerror(errno));
            }
            if(result == 0) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL, "socket sendto returned 0: %s", strerror(errno));
            }
        }
    }
}

static bool sfmc_lookupAddress(char *name, struct sockaddr *sa, SFLAddress *addr, int family)
{
    struct addrinfo *info = NULL;
    struct addrinfo hints = { 0 };
    hints.ai_socktype = SOCK_DGRAM; /* constrain this so we don't get lots of answers */
    hints.ai_family = family; /* PF_INET, PF_INET6 or 0 */
    int err = getaddrinfo(name, NULL, &hints, &info);
    if(err) {
        switch(err) {
        case EAI_NONAME: break;
        case EAI_NODATA: break;
        case EAI_AGAIN: break; /* loop and try again? */
        default: settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL, "getaddrinfo() error: %s", gai_strerror(err)); break;
        }
        return false;
    }
    
    if(info == NULL) return false;
    
    if(info->ai_addr) {
        /* answer is now in info - a linked list of answers with sockaddr values. */
        /* extract the address we want from the first one. */
        switch(info->ai_family) {
        case PF_INET:
            {
                struct sockaddr_in *ipsoc = (struct sockaddr_in *)info->ai_addr;
                addr->type = SFLADDRESSTYPE_IP_V4;
                addr->address.ip_v4.addr = ipsoc->sin_addr.s_addr;
                if(sa) memcpy(sa, info->ai_addr, info->ai_addrlen);
            }
            break;
        case PF_INET6:
            {
                struct sockaddr_in6 *ip6soc = (struct sockaddr_in6 *)info->ai_addr;
                addr->type = SFLADDRESSTYPE_IP_V6;
                memcpy(&addr->address.ip_v6, &ip6soc->sin6_addr, 16);
                if(sa) memcpy(sa, info->ai_addr, info->ai_addrlen);
            }
            break;
        default:
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL, "getaddrinfo: unexpected address family: %d", info->ai_family);
            return false;
            break;
        }
    }
    /* free the dynamically allocated data before returning */
    freeaddrinfo(info);
    return true;
}

static bool sfmc_syntaxOK(SFMCConfig *cfg, uint32_t line, uint32_t tokc, uint32_t tokcMin, uint32_t tokcMax, char *syntax) {
    if(tokc < tokcMin || tokc > tokcMax) {
        cfg->error = true;
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL, "syntax error on line %u: expected %s",
                                        line,
                                        syntax);
        return false;
    }
    return true;
}

static void sfmc_syntaxError(SFMCConfig *cfg, uint32_t line, char *msg) {
    cfg->error = true;
    settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL, "syntax error on line %u: %s",
                                    line,
                                    msg);
}    

static SFMCConfig *sfmc_readConfig(SFMC *sm)
{
    uint32_t rev_start = 0;
    uint32_t rev_end = 0;
    SFMCConfig *config = (SFMCConfig *)sfmc_calloc(sizeof(SFMCConfig));
    FILE *cfg = NULL;
    if((cfg = fopen(sm->configFile, "r")) == NULL) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING,"NULL, cannot open config file %s : %s", sm->configFile, strerror(errno));
        return NULL;
    }
    char line[SFMC_MAX_LINELEN+1];
    uint32_t lineNo = 0;
    char *tokv[5];
    uint32_t tokc;
    while(fgets(line, SFMC_MAX_LINELEN, cfg)) {
        lineNo++;
        char *p = line;
        /* comments start with '#' */
        p[strcspn(p, "#")] = '\0';
        /* 1 var and up to 3 value tokens, so detect up to 5 tokens overall */
        /* so we know if there was an extra one that should be flagged as a */
        /* syntax error. */
        tokc = 0;
        for(int i = 0; i < 5; i++) {
            size_t len;
            p += strspn(p, SFMC_SEPARATORS);
            if((len = strcspn(p, SFMC_SEPARATORS)) == 0) break;
            tokv[tokc++] = p;
            p += len;
            if(*p != '\0') *p++ = '\0';
        }

        if(tokc >=2) {
            settings.extensions.logger->log(EXTENSION_LOG_INFO,"NULL, line=%s tokc=%u tokv=<%s> <%s> <%s>",
                                            line,
                                            tokc,
                                            tokc > 0 ? tokv[0] : "",
                                            tokc > 1 ? tokv[1] : "",
                                            tokc > 2 ? tokv[2] : "");
        }

        if(tokc) {
            if(strcasecmp(tokv[0], "rev_start") == 0
               && sfmc_syntaxOK(config, lineNo, tokc, 2, 2, "rev_start=<int>")) {
                rev_start = strtol(tokv[1], NULL, 0);
            }
            else if(strcasecmp(tokv[0], "rev_end") == 0
                    && sfmc_syntaxOK(config, lineNo, tokc, 2, 2, "rev_end=<int>")) {
                rev_end = strtol(tokv[1], NULL, 0);
            }
            else if(strcasecmp(tokv[0], "sampling") == 0
                    && sfmc_syntaxOK(config, lineNo, tokc, 2, 2, "sampling=<int>")) {
                config->sampling_n = strtol(tokv[1], NULL, 0);
            }
            else if(strcasecmp(tokv[0], "sampling.memcache") == 0
                    && sfmc_syntaxOK(config, lineNo, tokc, 2, 2, "sampling.memcache=<int>")) {
                config->sampling_n = strtol(tokv[1], NULL, 0);
            }
            else if(strcasecmp(tokv[0], "polling") == 0 
                    && sfmc_syntaxOK(config, lineNo, tokc, 2, 2, "polling=<int>")) {
                config->polling_secs = strtol(tokv[1], NULL, 0);
            }
            else if(strcasecmp(tokv[0], "polling.memcache") == 0 
                    && sfmc_syntaxOK(config, lineNo, tokc, 2, 2, "polling.memcache=<int>")) {
                config->polling_secs = strtol(tokv[1], NULL, 0);
            }
            else if(strcasecmp(tokv[0], "agentIP") == 0
                    && sfmc_syntaxOK(config, lineNo, tokc, 2, 2, "agentIP=<IP address>|<IPv6 address>")) {
                if(sfmc_lookupAddress(tokv[1],
                                      NULL,
                                      &config->agentIP,
                                      0) == false) {
                    sfmc_syntaxError(config, lineNo, "agent address lookup failed");
                }
            }
            else if(strcasecmp(tokv[0], "collector") == 0
                    && sfmc_syntaxOK(config, lineNo, tokc, 2, 4, "collector=<IP address>[ <port>[ <priority>]]")) {
                if(config->num_collectors < SFMC_MAX_COLLECTORS) {
                    uint32_t i = config->num_collectors++;
                    if(sfmc_lookupAddress(tokv[1],
                                          &config->collectors[i].sa,
                                          &config->collectors[i].addr,
                                          0) == false) {
                        sfmc_syntaxError(config, lineNo, "collector address lookup failed");
                    }
                    config->collectors[i].port = tokc >= 3 ? strtol(tokv[2], NULL, 0) : 6343;
                    config->collectors[i].priority = tokc >= 4 ? strtol(tokv[3], NULL, 0) : 0;
                }
                else {
                    sfmc_syntaxError(config, lineNo, "exceeded max collectors");
                }
            }
            else if(strcasecmp(tokv[0], "header") == 0) { /* ignore */ }
            else if(strcasecmp(tokv[0], "agent") == 0) { /* ignore */ }
            else if(strncasecmp(tokv[0], "sampling.", 9) == 0) { /* ignore */ }
            else if(strncasecmp(tokv[0], "polling.", 8) == 0) { /* ignore */ }
            else {
                // sfmc_syntaxError(config, lineNo, "unknown var=value setting");
            }
        }
    }
    fclose(cfg);
    
    /* sanity checks... */
    
    if(config->agentIP.type == SFLADDRESSTYPE_UNDEFINED) {
        sfmc_syntaxError(config, 0, "agentIP=<IP address>|<IPv6 address>");
    }
    
    if((rev_start == rev_end) && !config->error) {
        return config;
    }
    else {
        free(config);
        return NULL;
    }
}

static void sfmc_apply_config(SFMC *sm, SFMCConfig *config)
{
    if(sm->config == config) return;
    SFMCConfig *oldConfig = sm->config;
    SEMLOCK_DO(sm->mutex) {
        sm->config = config;
    }
    if(oldConfig) free(oldConfig);
    if(config) sflow_init(sm);
}
    

// called from memcached.c every second or so
void sflow_tick(rel_time_t current_time) {

    SFMC *sm = &sfmc;
    sm->tick = current_time;

    if(sm->configTests == 0) {
        sflow_init(sm);
    }

    if(sm->configTests == 0 || (sm->tick % 10 == 0)) {
        sm->configTests++;
        settings.extensions.logger->log(EXTENSION_LOG_INFO, NULL, "checking for config file change <%s>", sm->configFile);
        struct stat statBuf;
        if(stat(sm->configFile, &statBuf) != 0) {
            /* config file missing */
            sfmc_apply_config(sm, NULL);
        }
        else if(statBuf.st_mtime != sm->configFile_modTime) {
            /* config file modified */
            settings.extensions.logger->log(EXTENSION_LOG_INFO, NULL, "config file changed");
            SFMCConfig *newConfig = sfmc_readConfig(sm);
            if(newConfig) {
                /* config OK - apply it */
                settings.extensions.logger->log(EXTENSION_LOG_INFO, NULL, "config OK");
                sfmc_apply_config(sm, newConfig);
                sm->configFile_modTime = statBuf.st_mtime;
            }
            else {
                /* bad config - ignore it (may be in transition) */
                settings.extensions.logger->log(EXTENSION_LOG_INFO, NULL, "config failed");
            }
        }
    }
    
    if(sm->agent && sm->config) {
        sfl_agent_tick(sm->agent, (time_t)sm->tick);
    }
}

static void sflow_init(SFMC *sm) {
    
    gettimeofday(&sm->start_time, NULL);

    if(sm->configFile == NULL) {
        sm->configFile = SFMC_DEFAULT_CONFIGFILE;
    }

    if(sm->config == NULL) return;

    if(sm->mutex == NULL) {
        sm->mutex = (pthread_mutex_t*)sfmc_calloc(sizeof(pthread_mutex_t));
        pthread_mutex_init(sm->mutex, NULL);
    }

    SEMLOCK_DO(sm->mutex) {
        /* create/re-create the agent */
        if(sm->agent) {
            sfl_agent_release(sm->agent);
            free(sm->agent);
        }
        sm->agent = (SFLAgent *)sfmc_calloc(sizeof(SFLAgent));
        
        /* open the sockets - one for v4 and another for v6 */
        if(sm->socket4 <= 0) {
            if((sm->socket4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL, "IPv4 send socket open failed : %s", strerror(errno));
        }
        if(sm->socket6 <= 0) {
            if((sm->socket6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1)
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL, "IPv6 send socket open failed : %s", strerror(errno));
        }
        
        /* initialize the agent with it's address, bootime, callbacks etc. */
        sfl_agent_init(sm->agent,
                       &sm->config->agentIP,
                       0, /* subAgentId */
                       sm->tick,
                       sm->tick,
                       sm,
                       sfmc_cb_alloc,
                       sfmc_cb_free,
                       sfmc_cb_error,
                       sfmc_cb_sendPkt);
        
        /* add a receiver */
        SFLReceiver *receiver = sfl_agent_addReceiver(sm->agent);
        /* add a <logicalEntity> datasource to represent this application instance */
        SFLDataSource_instance dsi;
        /* ds_class = <logicalEntity>, ds_index = 65537, ds_instance = 0 */
        /* $$$ should learn the ds_index from the config file */
        SFL_DS_SET(dsi, SFL_DSCLASS_LOGICAL_ENTITY, 65537, 0);

        /* add a poller for the counters */
        SFLPoller *poller = sfl_agent_addPoller(sm->agent, &dsi, sm, sfmc_cb_counters);
        sfl_poller_set_sFlowCpInterval(poller, sm->config->polling_secs);
        poller->myReceiver = receiver;
        
        /* add a sampler for the sampled operations */
        SFLSampler *sampler = sfl_agent_addSampler(sm->agent, &dsi);
        sfl_sampler_set_sFlowFsPacketSamplingRate(sampler, sm->config->sampling_n);
        sampler->myReceiver = receiver;

        if(sm->config->sampling_n) {
            /* seed the random number generator so that there is no
               synchronization even when a large cluster starts up all 
               at the exact same instant */
            /* could also read 4 bytes from /dev/urandom to do this */
            uint32_t hash = sm->start_time.tv_sec ^ sm->start_time.tv_usec;
            u_char *addr = sm->config->agentIP.address.ip_v6.addr;
            for(int i = 0; i < 16; i += 2) {
                hash *= 3;
                hash += ((addr[i] << 8) | addr[i+1]);
            }
            sfmc.sflow_random_seed = hash;
            sfmc.sflow_random_threshold = (sm->config->sampling_n == 1) ? 0 : ((uint32_t)-1 / sm->config->sampling_n);
        }
        else {
            sfmc.sflow_random_seed = 0;
        }
    }
}

