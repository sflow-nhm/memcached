/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Thread management for memcached.
 */
#include "memcached.h"
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#define ITEMS_PER_ALLOC 64

/* An item in the connection queue. */
typedef struct conn_queue_item CQ_ITEM;
struct conn_queue_item {
    int               sfd;
    enum conn_states  init_state;
    int               event_flags;
    int               read_buffer_size;
    enum network_transport     transport;
    CQ_ITEM          *next;
};

/* A connection queue. */
typedef struct conn_queue CQ;
struct conn_queue {
    CQ_ITEM *head;
    CQ_ITEM *tail;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
};

/* Connection lock around accepting new connections */
pthread_mutex_t conn_lock = PTHREAD_MUTEX_INITIALIZER;

/* Lock for global stats */
static pthread_mutex_t stats_lock;

/* Free list of CQ_ITEM structs */
static CQ_ITEM *cqi_freelist;
static pthread_mutex_t cqi_freelist_lock;

static LIBEVENT_DISPATCHER_THREAD dispatcher_thread;

/*
 * Each libevent instance has a wakeup pipe, which other threads
 * can use to signal that they've put a new connection on its queue.
 */
static LIBEVENT_THREAD *threads;
LIBEVENT_THREAD tap_thread;

/*
 * Number of worker threads that have finished setting themselves up.
 */
static int init_count = 0;
static pthread_mutex_t init_lock;
static pthread_cond_t init_cond;


static void thread_libevent_process(int fd, short which, void *arg);
static void libevent_tap_process(int fd, short which, void *arg);

/*
 * Initializes a connection queue.
 */
static void cq_init(CQ *cq) {
    pthread_mutex_init(&cq->lock, NULL);
    pthread_cond_init(&cq->cond, NULL);
    cq->head = NULL;
    cq->tail = NULL;
}

/*
 * Looks for an item on a connection queue, but doesn't block if there isn't
 * one.
 * Returns the item, or NULL if no item is available
 */
static CQ_ITEM *cq_pop(CQ *cq) {
    CQ_ITEM *item;

    pthread_mutex_lock(&cq->lock);
    item = cq->head;
    if (NULL != item) {
        cq->head = item->next;
        if (NULL == cq->head)
            cq->tail = NULL;
    }
    pthread_mutex_unlock(&cq->lock);

    return item;
}

/*
 * Adds an item to a connection queue.
 */
static void cq_push(CQ *cq, CQ_ITEM *item) {
    item->next = NULL;

    pthread_mutex_lock(&cq->lock);
    if (NULL == cq->tail)
        cq->head = item;
    else
        cq->tail->next = item;
    cq->tail = item;
    pthread_cond_signal(&cq->cond);
    pthread_mutex_unlock(&cq->lock);
}

/*
 * Returns a fresh connection queue item.
 */
static CQ_ITEM *cqi_new(void) {
    CQ_ITEM *item = NULL;
    pthread_mutex_lock(&cqi_freelist_lock);
    if (cqi_freelist) {
        item = cqi_freelist;
        cqi_freelist = item->next;
    }
    pthread_mutex_unlock(&cqi_freelist_lock);

    if (NULL == item) {
        int i;

        /* Allocate a bunch of items at once to reduce fragmentation */
        item = malloc(sizeof(CQ_ITEM) * ITEMS_PER_ALLOC);
        if (NULL == item)
            return NULL;

        /*
         * Link together all the new items except the first one
         * (which we'll return to the caller) for placement on
         * the freelist.
         */
        for (i = 2; i < ITEMS_PER_ALLOC; i++)
            item[i - 1].next = &item[i];

        pthread_mutex_lock(&cqi_freelist_lock);
        item[ITEMS_PER_ALLOC - 1].next = cqi_freelist;
        cqi_freelist = &item[1];
        pthread_mutex_unlock(&cqi_freelist_lock);
    }

    return item;
}


/*
 * Frees a connection queue item (adds it to the freelist.)
 */
static void cqi_free(CQ_ITEM *item) {
    pthread_mutex_lock(&cqi_freelist_lock);
    item->next = cqi_freelist;
    cqi_freelist = item;
    pthread_mutex_unlock(&cqi_freelist_lock);
}


/*
 * Creates a worker thread.
 */
static void create_worker(void *(*func)(void *), void *arg) {
    pthread_t       thread;
    pthread_attr_t  attr;
    int             ret;

    pthread_attr_init(&attr);

    if ((ret = pthread_create(&thread, &attr, func, arg)) != 0) {
        fprintf(stderr, "Can't create thread: %s\n",
                strerror(ret));
        exit(1);
    }
}

/*
 * Sets whether or not we accept new connections.
 */
void accept_new_conns(const bool do_accept) {
    pthread_mutex_lock(&conn_lock);
    do_accept_new_conns(do_accept);
    pthread_mutex_unlock(&conn_lock);
}
/****************************** LIBEVENT THREADS *****************************/

/*
 * Set up a thread's information.
 */
static void setup_thread(LIBEVENT_THREAD *me, bool tap) {
    me->base = event_init();
    if (! me->base) {
        fprintf(stderr, "Can't allocate event base\n");
        exit(1);
    }

    /* Listen for notifications from other threads */
    event_set(&me->notify_event, me->notify_receive_fd,
              EV_READ | EV_PERSIST,
              tap ? libevent_tap_process : thread_libevent_process, me);
    event_base_set(me->base, &me->notify_event);

    if (event_add(&me->notify_event, 0) == -1) {
        fprintf(stderr, "Can't monitor libevent notify pipe\n");
        exit(1);
    }

    if (!tap) {
        me->new_conn_queue = malloc(sizeof(struct conn_queue));
        if (me->new_conn_queue == NULL) {
            perror("Failed to allocate memory for connection queue");
            exit(EXIT_FAILURE);
        }
        cq_init(me->new_conn_queue);
    }

    if ((pthread_mutex_init(&me->mutex, NULL) != 0)) {
        perror("Failed to initialize mutex");
        exit(EXIT_FAILURE);
    }

    me->suffix_cache = cache_create("suffix", SUFFIX_SIZE, sizeof(char*),
                                    NULL, NULL);
    if (me->suffix_cache == NULL) {
        fprintf(stderr, "Failed to create suffix cache\n");
        exit(EXIT_FAILURE);
    }
}

/*
 * Worker thread: main event loop
 */
static void *worker_libevent(void *arg) {
    LIBEVENT_THREAD *me = arg;

    /* Any per-thread setup can happen here; thread_init() will block until
     * all threads have finished initializing.
     */

    pthread_mutex_lock(&init_lock);
    init_count++;
    pthread_cond_signal(&init_cond);
    pthread_mutex_unlock(&init_lock);

    event_base_loop(me->base, 0);
    return NULL;
}


/*
 * Processes an incoming "handle a new connection" item. This is called when
 * input arrives on the libevent wakeup pipe.
 */
static void thread_libevent_process(int fd, short which, void *arg) {
    LIBEVENT_THREAD *me = arg;
    CQ_ITEM *item;
    char buf[1];

    if (read(fd, buf, 1) != 1)
        if (settings.verbose > 0)
            fprintf(stderr, "Can't read from libevent pipe\n");

    item = cq_pop(me->new_conn_queue);

    if (NULL != item) {
        conn *c = conn_new(item->sfd, item->init_state, item->event_flags,
                           item->read_buffer_size, item->transport, me->base);
        if (c == NULL) {
            if (IS_UDP(item->transport)) {
                fprintf(stderr, "Can't listen for events on UDP socket\n");
                exit(1);
            } else {
                if (settings.verbose > 0) {
                    fprintf(stderr, "Can't listen for events on fd %d\n",
                        item->sfd);
                }
                close(item->sfd);
            }
        } else {
            c->thread = me;
        }
        cqi_free(item);
    }

    conn* pending = NULL;
    pthread_mutex_lock(&me->mutex);
    if (me->pending_io != NULL) {
        pending = me->pending_io;
        me->pending_io = NULL;
    }
    pthread_mutex_unlock(&me->mutex);
    if (pending != NULL) {
        do {
            conn *c = pending;
            pending = pending->next;
            c->next = NULL;
            assert(me == c->thread);
            event_add(&c->event, 0);
            drive_machine(c);
        } while (pending != NULL);
    }
}

static void libevent_tap_process(int fd, short which, void *arg) {
    LIBEVENT_THREAD *me = arg;
    char buf[1];

    if (read(fd, buf, 1) != 1)
        if (settings.verbose > 0)
            fprintf(stderr, "Can't read from libevent pipe\n");

    conn* pending = NULL;
    pthread_mutex_lock(&me->mutex);
    if (me->pending_io != NULL) {
        pending = me->pending_io;
        me->pending_io = NULL;
    }
    pthread_mutex_unlock(&me->mutex);
    if (pending != NULL) {
        do {
            conn *c = pending;
            pending = pending->next;
            c->next = NULL;
            assert(me == c->thread);
            event_add(&c->event, 0);
            drive_machine(c);
        } while (pending != NULL);
    }
}

void notify_io_complete(const void *cookie, ENGINE_ERROR_CODE status)
{
    struct conn *conn = (struct conn *)cookie;
    conn->aiostat = status;
    LIBEVENT_THREAD *thr = conn->thread;

    pthread_mutex_lock(&thr->mutex);
    assert(conn->next == NULL);
    conn->next = thr->pending_io;
    thr->pending_io = conn;
    pthread_mutex_unlock(&thr->mutex);

    /* kick the thread in the butt */
    if (write(thr->notify_send_fd, "", 1) != 1) {
        perror("Writing to thread notify pipe");
    }
}

/* Which thread we assigned a connection to most recently. */
static int last_thread = -1;

/*
 * Dispatches a new connection to another thread. This is only ever called
 * from the main thread, either during initialization (for UDP) or because
 * of an incoming connection.
 */
void dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags,
                       int read_buffer_size, enum network_transport transport) {
    CQ_ITEM *item = cqi_new();
    int tid = (last_thread + 1) % settings.num_threads;

    LIBEVENT_THREAD *thread = threads + tid;

    last_thread = tid;

    item->sfd = sfd;
    item->init_state = init_state;
    item->event_flags = event_flags;
    item->read_buffer_size = read_buffer_size;
    item->transport = transport;

    cq_push(thread->new_conn_queue, item);

    MEMCACHED_CONN_DISPATCH(sfd, thread->thread_id);
    if (write(thread->notify_send_fd, "", 1) != 1) {
        perror("Writing to thread notify pipe");
    }
}

/*
 * Returns true if this is the thread that listens for new TCP connections.
 */
int is_listen_thread() {
#ifndef __WIN32__
    return pthread_self() == dispatcher_thread.thread_id;
#else
    pthread_t tid = pthread_self();
    return(tid.p == dispatcher_thread.thread_id.p && tid.x == dispatcher_thread.thread_id.x);
#endif
}


/******************************* GLOBAL STATS ******************************/

void STATS_LOCK() {
    pthread_mutex_lock(&stats_lock);
}

void STATS_UNLOCK() {
    pthread_mutex_unlock(&stats_lock);
}

void threadlocal_stats_clear(struct thread_stats *stats) {
    stats->cmd_get = 0;
    stats->get_misses = 0;
    stats->delete_misses = 0;
    stats->incr_misses = 0;
    stats->decr_misses = 0;
    stats->incr_hits = 0;
    stats->decr_hits = 0;
    stats->cas_misses = 0;
    stats->bytes_written = 0;
    stats->bytes_read = 0;
    stats->cmd_flush = 0;
    stats->conn_yields = 0;
    stats->auth_cmds = 0;
    stats->auth_errors = 0;

    memset(stats->slab_stats, 0,
           sizeof(struct slab_stats) * MAX_NUMBER_OF_SLAB_CLASSES);
}

void threadlocal_stats_reset(struct thread_stats *thread_stats) {
    int ii;
    for (ii = 0; ii < settings.num_threads; ++ii) {
        pthread_mutex_lock(&thread_stats[ii].mutex);
        threadlocal_stats_clear(&thread_stats[ii]);
        pthread_mutex_unlock(&thread_stats[ii].mutex);
    }
}

void threadlocal_stats_aggregate(struct thread_stats *thread_stats, struct thread_stats *stats) {
    int ii, sid;
    for (ii = 0; ii < settings.num_threads; ++ii) {
        pthread_mutex_lock(&thread_stats[ii].mutex);

        stats->cmd_get += thread_stats[ii].cmd_get;
        stats->get_misses += thread_stats[ii].get_misses;
        stats->delete_misses += thread_stats[ii].delete_misses;
        stats->decr_misses += thread_stats[ii].decr_misses;
        stats->incr_misses += thread_stats[ii].incr_misses;
        stats->decr_hits += thread_stats[ii].decr_hits;
        stats->incr_hits += thread_stats[ii].incr_hits;
        stats->cas_misses += thread_stats[ii].cas_misses;
        stats->bytes_read += thread_stats[ii].bytes_read;
        stats->bytes_written += thread_stats[ii].bytes_written;
        stats->cmd_flush += thread_stats[ii].cmd_flush;
        stats->conn_yields += thread_stats[ii].conn_yields;
        stats->auth_cmds += thread_stats[ii].auth_cmds;
        stats->auth_errors += thread_stats[ii].auth_errors;

        for (sid = 0; sid < MAX_NUMBER_OF_SLAB_CLASSES; sid++) {
            stats->slab_stats[sid].cmd_set +=
                thread_stats[ii].slab_stats[sid].cmd_set;
            stats->slab_stats[sid].get_hits +=
                thread_stats[ii].slab_stats[sid].get_hits;
            stats->slab_stats[sid].delete_hits +=
                thread_stats[ii].slab_stats[sid].delete_hits;
            stats->slab_stats[sid].cas_hits +=
                thread_stats[ii].slab_stats[sid].cas_hits;
            stats->slab_stats[sid].cas_badval +=
                thread_stats[ii].slab_stats[sid].cas_badval;
        }

        pthread_mutex_unlock(&thread_stats[ii].mutex);
    }
}

void slab_stats_aggregate(struct thread_stats *stats, struct slab_stats *out) {
    int sid;

    out->cmd_set = 0;
    out->get_hits = 0;
    out->delete_hits = 0;
    out->cas_hits = 0;
    out->cas_badval = 0;

    for (sid = 0; sid < MAX_NUMBER_OF_SLAB_CLASSES; sid++) {
        out->cmd_set += stats->slab_stats[sid].cmd_set;
        out->get_hits += stats->slab_stats[sid].get_hits;
        out->delete_hits += stats->slab_stats[sid].delete_hits;
        out->cas_hits += stats->slab_stats[sid].cas_hits;
        out->cas_badval += stats->slab_stats[sid].cas_badval;
    }
}

/*
 * Initializes the thread subsystem, creating various worker threads.
 *
 * nthreads  Number of worker event handler threads to spawn
 * main_base Event base for main thread
 */
void thread_init(int nthreads, struct event_base *main_base) {
    int i;

#ifdef __WIN32__
    struct sockaddr_in serv_addr;
    int sockfd;

    if ((sockfd = createLocalListSock(&serv_addr)) < 0)
        exit(1);
#endif

    pthread_mutex_init(&stats_lock, NULL);

    pthread_mutex_init(&init_lock, NULL);
    pthread_cond_init(&init_cond, NULL);

    pthread_mutex_init(&cqi_freelist_lock, NULL);
    cqi_freelist = NULL;

    threads = calloc(nthreads, sizeof(LIBEVENT_THREAD));
    if (! threads) {
        perror("Can't allocate thread descriptors");
        exit(1);
    }

    dispatcher_thread.base = main_base;
    dispatcher_thread.thread_id = pthread_self();

    for (i = 0; i < nthreads; i++) {
        int fds[2];
#ifndef __WIN32__
        if (pipe(fds)) {
#else
        if (createLocalSocketPair(sockfd,fds,&serv_addr) == -1) {
#endif
            perror("Can't create notify pipe");
            exit(1);
        }

        threads[i].notify_receive_fd = fds[0];
        threads[i].notify_send_fd = fds[1];
        threads[i].index = i;

        setup_thread(&threads[i], false);
#ifdef __WIN32__
        if (i == (nthreads - 1))
            shutdown(sockfd, 2);
#endif
    }

    /* Create threads after we've done all the libevent setup. */
    for (i = 0; i < nthreads; i++) {
        create_worker(worker_libevent, &threads[i]);
    }

    int fds[2];
    if (pipe(fds)) {
        perror("Can't create notify pipe");
        exit(1);
    }

    tap_thread.notify_receive_fd = fds[0];
    tap_thread.notify_send_fd = fds[1];
    tap_thread.index = i;
    setup_thread(&tap_thread, true);
    create_worker(worker_libevent, &tap_thread);

    /* Wait for all the threads to set themselves up before returning. */
    pthread_mutex_lock(&init_lock);
    while (init_count < nthreads) {
        pthread_cond_wait(&init_cond, &init_lock);
    }
    pthread_mutex_unlock(&init_lock);
}

