#ifndef SFLOW_MC_H
#define SFLOW_MC_H 1

#include "config.h"
#include "memcached.h"
#include <sys/types.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h> /* for PRIu64 etc. */

#ifdef ENABLE_SFLOW
void sflow_tick(rel_time_t now);
void sflow_command_start(struct conn *c);
void sflow_sample(struct conn *c, const void *key, size_t keylen, uint32_t nkeys, size_t value_bytes, uint32_t status);
#define SFLOW_TICK(now) sflow_tick(now)
#define SFLOW_COMMAND_START(c) sflow_command_start(c)
#define SFLOW_SAMPLE(c, key, keylen, nkeys, bytes, status) sflow_sample(c, key, keylen, nkeys, bytes, status)
#else
#define SFLOW_TICK(now)
#define SFLOW_COMMAND_START(c)
#define SFLOW_SAMPLE(c, key, keylen, nkeys, bytes, status)
#endif

#endif /* SFLOW_MC_H */

