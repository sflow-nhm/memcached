#ifndef SFLOW_MC_H
#define SFLOW_MC_H 1

#include "config.h"
#include "memcached.h"
#include <sys/types.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h> /* for PRIu64 etc. */

#ifdef ENABLE_SFLOW
extern uint32_t sflow_sample_pool;
extern uint32_t sflow_skip;

#define SFMC_ATOMIC_FETCH_ADD(_c, _inc) __sync_fetch_and_add(&(_c), (_inc))
#define SFMC_ATOMIC_INC(_c) SFMC_ATOMIC_FETCH_ADD((_c), 1)
#define SFMC_ATOMIC_DEC(_c) SFMC_ATOMIC_FETCH_ADD((_c), -1)

void sflow_tick(rel_time_t now);
void sflow_command_start(struct conn *c);
void sflow_sample(struct conn *c, const void *key, size_t keylen, uint32_t nkeys, size_t value_bytes, int status);

#define SFLOW_TICK(now) sflow_tick(now)

#define SFLOW_COMMAND_START(c)			     \
  do {						     \
    SFMC_ATOMIC_INC(sflow_sample_pool);		     \
    if(unlikely(SFMC_ATOMIC_DEC(sflow_skip) == 1)) { \
      sflow_command_start(c);			     \
    }						     \
  } while(0)

#define SFLOW_SAMPLE(c, key, keylen, nkeys, bytes, status)		\
  do {									\
    if(unlikely((c)->sflow_start_time.tv_sec)) {			\
      sflow_sample((c), (key), (keylen), (nkeys), (bytes), (status));	\
    }									\
  } while(0)
#else

#define SFLOW_TICK(now)
#define SFLOW_COMMAND_START(c)
#define SFLOW_SAMPLE(c, key, keylen, nkeys, bytes, slab_op)

#endif

#endif /* SFLOW_MC_H */

