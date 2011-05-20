#ifndef SFLOW_MC_H
#define SFLOW_MC_H 1

#include "config.h"
#include "memcached.h"
#include <sys/types.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h> /* for PRIu64 etc. */

#ifdef ENABLE_SFLOW

typedef enum  {
  SFMC_CMD_OTHER    = 0,
  SFMC_CMD_SET      = 1,
  SFMC_CMD_ADD      = 2,
  SFMC_CMD_REPLACE  = 3,
  SFMC_CMD_APPEND   = 4,
  SFMC_CMD_PREPEND  = 5,
  SFMC_CMD_CAS      = 6,
  SFMC_CMD_GET      = 7,
  SFMC_CMD_GETS     = 8,
  SFMC_CMD_INCR     = 9,
  SFMC_CMD_DECR     = 10,
  SFMC_CMD_DELETE   = 11,
  SFMC_CMD_STATS    = 12,
  SFMC_CMD_FLUSH    = 13,
  SFMC_CMD_VERSION  = 14,
  SFMC_CMD_QUIT     = 15,
} SFLMemcache_cmd;

void sflow_tick(rel_time_t now);
void sflow_sample_test(struct conn *c);
void sflow_sample(SFLMemcache_cmd cmd, struct conn *c, const void *key, size_t keylen, uint32_t nkeys, size_t value_bytes, int status);

#define SFLOW_TICK(now) sflow_tick(now)
#define SFLOW_SAMPLE_TEST(c) sflow_sample_test(c)
#define SFLOW_SAMPLE(cmd, c, key, keylen, nkeys, bytes, status)		      \
  do {									      \
    if(unlikely((c)->sflow_start_time.tv_sec)) {			      \
      sflow_sample((cmd), (c), (key), (keylen), (nkeys), (bytes), (status));  \
    }									      \
  } while(0)

#else

#define SFLOW_TICK(now)
#define SFLOW_COMMAND_START(c)
#define SFLOW_SAMPLE(cmd, c, key, keylen, nkeys, bytes, slab_op)

#endif

#endif /* SFLOW_MC_H */

