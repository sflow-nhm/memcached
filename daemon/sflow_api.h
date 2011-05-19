/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* Copyright (c) 2002-2011 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#ifndef SFLOW_API_H
#define SFLOW_API_H 1

#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#include <arpa/inet.h>
#endif /*_WIN32 */
#include <errno.h>
#include <string.h>
#include <sys/types.h>

/* ================== sFlow v5 structure definitions (www.sflow.org) ==================*/

typedef struct {
  uint32_t addr;
} SFLIPv4;

typedef struct {
  u_char addr[16];
} SFLIPv6;

typedef union _SFLAddress_value {
  SFLIPv4 ip_v4;
  SFLIPv6 ip_v6;
} SFLAddress_value;

enum SFLAddress_type {
  SFLADDRESSTYPE_UNDEFINED = 0,
  SFLADDRESSTYPE_IP_V4 = 1,
  SFLADDRESSTYPE_IP_V6 = 2
};

typedef struct _SFLAddress {
  uint32_t type;           /* enum SFLAddress_type */
  SFLAddress_value address;
} SFLAddress;

enum SFL_DSCLASS {
  SFL_DSCLASS_IFINDEX=0,
  SFL_DSCLASS_VLAN=1,
  SFL_DSCLASS_PHYSICAL_ENTITY=2,
  SFL_DSCLASS_LOGICAL_ENTITY=3
};

/* Packet header data */

#define SFL_DEFAULT_HEADER_SIZE 128
#define SFL_DEFAULT_COLLECTOR_PORT 6343
#define SFL_DEFAULT_SAMPLING_RATE 400
#define SFL_DEFAULT_POLLING_INTERVAL 30

/* Extended data types */

typedef struct _SFLString {
  uint32_t len;
  char *str;
} SFLString;

/* Extended socket information,
   Must be filled in for all application transactions associated with a network socket
   Omit if transaction associated with non-network IPC  */

/* IPv4 Socket */
/* opaque = flow_data; enterprise = 0; format = 2100 */
typedef struct _SFLExtended_socket_ipv4 {
  uint32_t protocol;     /* IP Protocol (e.g. TCP = 6, UDP = 17) */
  SFLIPv4 local_ip;      /* local IP address */
  SFLIPv4 remote_ip;     /* remote IP address */
  uint32_t local_port;   /* TCP/UDP local port number or equivalent */
  uint32_t remote_port;  /* TCP/UDP remote port number of equivalent */
} SFLExtended_socket_ipv4;

#define XDRSIZ_SFLEXTENDED_SOCKET4 20 

/* IPv6 Socket */
/* opaque = flow_data; enterprise = 0; format = 2101 */
typedef struct _SFLExtended_socket_ipv6 {
  uint32_t protocol;     /* IP Protocol (e.g. TCP = 6, UDP = 17) */
  SFLIPv6 local_ip;      /* local IP address */
  SFLIPv6 remote_ip;     /* remote IP address */
  uint32_t local_port;   /* TCP/UDP local port number or equivalent */
  uint32_t remote_port;  /* TCP/UDP remote port number of equivalent */
} SFLExtended_socket_ipv6;

#define XDRSIZ_SFLEXTENDED_SOCKET6 44

typedef enum  {
  SFMC_PROT_OTHER   = 0,
  SFMC_PROT_ASCII   = 1,
  SFMC_PROT_BINARY  = 2,
} SFLMemcache_prot;

#if 0 /* this one moved to sflow_mc.h to expose it to memcached.c */
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
#endif

typedef enum  {
  SFMC_OP_UNKNOWN      = 0,
  SFMC_OP_OK           = 1,
  SFMC_OP_ERROR        = 2,
  SFMC_OP_CLIENT_ERROR = 3,
  SFMC_OP_SERVER_ERROR = 4,
  SFMC_OP_STORED       = 5,
  SFMC_OP_NOT_STORED   = 6,
  SFMC_OP_EXISTS       = 7,
  SFMC_OP_NOT_FOUND    = 8,
  SFMC_OP_DELETED      = 9,
} SFLMemcache_operation_status;

typedef struct _SFLSampled_memcache {
  uint32_t protocol;    /* SFLMemcache_prot */
  uint32_t command;     /* SFLMemcache_cmd */
  SFLString key;        /* up to 255 chars */
  uint32_t nkeys;    
  uint32_t value_bytes;
  uint32_t duration_uS;
  uint32_t status;      /* SFLMemcache_operation_status */
} SFLSampled_memcache;


enum SFLFlow_type_tag {
  /* enterprise = 0, format = ... */
  SFLFLOW_EX_SOCKET4      = 2100,
  SFLFLOW_EX_SOCKET6      = 2101,
  SFLFLOW_MEMCACHE        = 2200,
};

typedef union _SFLFlow_type {
  SFLSampled_memcache memcache;
  SFLExtended_socket_ipv4 socket4;
  SFLExtended_socket_ipv6 socket6;
} SFLFlow_type;

typedef struct _SFLFlow_sample_element {
  struct _SFLFlow_sample_element *nxt;
  uint32_t tag;  /* SFLFlow_type_tag */
  uint32_t length;
  SFLFlow_type flowType;
} SFLFlow_sample_element;

enum SFL_sample_tag {
  SFLFLOW_SAMPLE = 1,              /* enterprise = 0 : format = 1 */
  SFLCOUNTERS_SAMPLE = 2,          /* enterprise = 0 : format = 2 */
};
  
/* Format of a single flow sample */

typedef struct _SFLFlow_sample {
  /* uint32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* uint32_t length; */
  uint32_t sequence_number;      /* Incremented with each flow sample
				    generated */
  uint32_t source_id;            /* fsSourceId */
  uint32_t sampling_rate;        /* fsPacketSamplingRate */
  uint32_t sample_pool;          /* Total number of packets that could have been
				    sampled (i.e. packets skipped by sampling
				    process + total number of samples) */
  uint32_t drops;                /* Number of times a packet was dropped due to
				    lack of resources */
  uint32_t input;                /* SNMP ifIndex of input interface.
				    0 if interface is not known. */
  uint32_t output;               /* SNMP ifIndex of output interface,
				    0 if interface is not known.
				    Set most significant bit to indicate
				    multiple destination interfaces
				    (i.e. in case of broadcast or multicast)
				    and set lower order bits to indicate
				    number of destination interfaces.
				    Examples:
				    0x00000002  indicates ifIndex = 2
				    0x00000000  ifIndex unknown.
				    0x80000007  indicates a packet sent
				    to 7 interfaces.
				    0x80000000  indicates a packet sent to
				    an unknown number of
				    interfaces greater than 1.*/
  uint32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_sample;


/* Counter types */

#define XDRSIZ_SFLHOST_VRT_NIO_COUNTERS 40

typedef struct _SFLMemcache_counters {
  uint32_t uptime;     /* Number of seconds this server has been running */
  uint32_t rusage_user;    /* Accumulated user time for this process (ms)*/
  uint32_t rusage_system;  /* Accumulated system time for this process (ms)*/
  uint32_t curr_connections; /* Number of open connections */
  uint32_t total_connections; /* Total number of connections opened since
				 the server started running */
  uint32_t connection_structures; /* Number of connection structures
				     allocated by the server */
  uint32_t cmd_get;        /* Cumulative number of retrieval requests */
  uint32_t cmd_set;        /* Cumulative number of storage requests */
  uint32_t cmd_flush;      /* */
  uint32_t get_hits;       /* Number of keys that have been requested and
			      found present */
  uint32_t get_misses;     /* Number of items that have been requested
			      and not found */
  uint32_t delete_misses;
  uint32_t delete_hits;
  uint32_t incr_misses;
  uint32_t incr_hits;
  uint32_t decr_misses;
  uint32_t decr_hits;
  uint32_t cas_misses;
  uint32_t cas_hits;
  uint32_t cas_badval;
  uint32_t auth_cmds;
  uint32_t auth_errors;
  uint64_t bytes_read;
  uint64_t bytes_written;
  uint32_t limit_maxbytes;
  uint32_t accepting_conns;
  uint32_t listen_disabled_num;
  uint32_t threads;
  uint32_t conn_yields;
  uint64_t bytes;
  uint32_t curr_items;
  uint32_t total_items;
  uint32_t evictions;
} SFLMemcache_counters;

#define XDRSIZ_SFLMEMCACHE_COUNTERS (36*4)

/* Counters data */

enum SFLCounters_type_tag {
  /* enterprise = 0, format = ... */
  SFLCOUNTERS_MEMCACHE      = 2200, /* memcached counters */
};

typedef union _SFLCounters_type {
  SFLMemcache_counters memcache;
} SFLCounters_type;

typedef struct _SFLCounters_sample_element {
  struct _SFLCounters_sample_element *nxt; /* linked list */
  uint32_t tag; /* SFLCounters_type_tag */
  uint32_t length;
  SFLCounters_type counterBlock;
} SFLCounters_sample_element;

typedef struct _SFLCounters_sample {
  /* uint32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* uint32_t length; */
  uint32_t sequence_number;    /* Incremented with each counters sample
				  generated by this source_id */
  uint32_t source_id;          /* fsSourceId */
  uint32_t num_elements;
  SFLCounters_sample_element *elements;
} SFLCounters_sample;

#define SFLADD_ELEMENT(_sm, _el) do { (_el)->nxt = (_sm)->elements; (_sm)->elements = (_el); } while(0)

/* Format of a sample datagram */

enum SFLDatagram_version {
  SFLDATAGRAM_VERSION2 = 2,
  SFLDATAGRAM_VERSION4 = 4,
  SFLDATAGRAM_VERSION5 = 5
};

typedef struct _SFLSample_datagram_hdr {
  uint32_t datagram_version;      /* (enum SFLDatagram_version) = VERSION5 = 5 */
  SFLAddress agent_address;        /* IP address of sampling agent */
  uint32_t sub_agent_id;          /* Used to distinguishing between datagram
				     streams from separate agent sub entities
				     within an device. */
  uint32_t sequence_number;       /* Incremented with each sample datagram
				     generated */
  uint32_t uptime;                /* Current time (in milliseconds since device
				     last booted). Should be set as close to
				     datagram transmission time as possible.*/
  uint32_t num_records;           /* Number of tag-len-val flow/counter records to follow */
} SFLSample_datagram_hdr;


/* =============== sFlow agent API ==================*/

#define SFL_MAX_DATAGRAM_SIZE 1500
#define SFL_MIN_DATAGRAM_SIZE 200
#define SFL_DEFAULT_DATAGRAM_SIZE 1400
#define SFL_DATA_PAD 400

typedef struct _SFLDataSource_instance {
  uint32_t ds_class;
  uint32_t ds_index;
  uint32_t ds_instance;
} SFLDataSource_instance;

#define SFL_FLOW_SAMPLE_TYPE SFLFlow_sample
#define SFL_COUNTERS_SAMPLE_TYPE SFLCounters_sample
#define SFL_DS_DATASOURCE(dsi) (((dsi).ds_class << 24) + (dsi).ds_index)
#define SFL_DS_INSTANCE(dsi) (dsi).ds_instance
#define SFL_DS_CLASS(dsi) (dsi).ds_class
#define SFL_DS_INDEX(dsi) (dsi).ds_index
#define SFL_DS_SET(dsi,clss,indx,inst)		\
  do {						\
    (dsi).ds_class = (clss);			\
    (dsi).ds_index = (indx);			\
    (dsi).ds_instance = (inst);			\
  } while(0)

#define SFL_SAMPLECOLLECTOR_DATA_QUADS (SFL_MAX_DATAGRAM_SIZE + SFL_DATA_PAD) / sizeof(uint32_t)

typedef struct _SFLSampleCollector {
  uint32_t data[SFL_SAMPLECOLLECTOR_DATA_QUADS];
  uint32_t *datap; /* packet fill pointer */
  uint32_t pktlen; /* accumulated size */
  uint32_t packetSeqNo;
  uint32_t numSamples;
} SFLSampleCollector;

struct _SFLAgent;  /* forward decl */

typedef struct _SFLReceiver {
  struct _SFLReceiver *nxt;
  uint32_t sFlowRcvrMaximumDatagramSize;
  uint32_t sFlowRcvrDatagramVersion;
  struct _SFLAgent *agent;
  SFLSampleCollector sampleCollector;
} SFLReceiver;

typedef struct _SFLSampler {
  struct _SFLSampler *nxt;
  SFLDataSource_instance dsi;
  uint32_t sFlowFsPacketSamplingRate;
  struct _SFLAgent *agent;
  SFLReceiver *myReceiver;
  uint32_t skip;
  uint32_t samplePool;
  uint32_t dropEvents;
  uint32_t flowSampleSeqNo;
} SFLSampler;

/* declare */
struct _SFLPoller;

typedef void (*getCountersFn_t)(void *magic,   /* callback to get counters */
				struct _SFLPoller *sampler,    /* called with self */
				SFL_COUNTERS_SAMPLE_TYPE *cs); /* struct to fill in */

typedef struct _SFLPoller {
  struct _SFLPoller *nxt;
  SFLDataSource_instance dsi;
  time_t sFlowCpInterval;
  struct _SFLAgent *agent;
  void *magic;             /* ptr to pass back in getCountersFn() */
  getCountersFn_t getCountersFn;
  SFLReceiver *myReceiver;
  time_t countersCountdown;
  uint32_t countersSampleSeqNo;
} SFLPoller;

typedef void *(*allocFn_t)(void *magic,   /* callback to allocate space on heap */
			   struct _SFLAgent *agent,   /* called with self */
			   size_t bytes);             /* bytes requested */

typedef int (*freeFn_t)(void *magic,      /* callback to free space on heap */
			struct _SFLAgent *agent,      /* called with self */
			void *obj);                   /* obj to free */

typedef void (*errorFn_t)(void *magic,    /* callback to log error message */
			  struct _SFLAgent *agent,    /* called with self */
			  char *msg);                 /* error message */

typedef void (*sendFn_t)(void *magic,     /* optional override fn to send packet */
			 struct _SFLAgent *agent,
			 SFLReceiver *receiver,
			 u_char *pkt,
			 uint32_t pktLen);

typedef struct _SFLAgent {
  SFLSampler *samplers;   /* the list of samplers */
  SFLPoller  *pollers;    /* the list of samplers */
  SFLReceiver *receivers; /* the array of receivers */
  time_t bootTime;        /* time when we booted or started */
  time_t now;             /* time now */
  SFLAddress myIP;        /* IP address of this node */
  uint32_t subId;        /* sub_agent_id */
  void *magic;            /* ptr to pass back in logging and alloc fns */
  allocFn_t allocFn;
  freeFn_t freeFn;
  errorFn_t errorFn;
  sendFn_t sendFn;
} SFLAgent;

/* call this at the start with a newly created agent */
void sfl_agent_init(SFLAgent *agent,
		    SFLAddress *myIP, /* IP address of this agent */
		    uint32_t subId,   /* agent_sub_id */
		    time_t bootTime,  /* agent boot time */
		    time_t now,       /* time now */
		    void *magic,      /* ptr to pass back in logging and alloc fns */
		    allocFn_t allocFn,
		    freeFn_t freeFn,
		    errorFn_t errorFn,
		    sendFn_t sendFn);

/* call this to create samplers */
SFLSampler *sfl_agent_addSampler(SFLAgent *agent, SFLDataSource_instance *pdsi);

/* call this to create pollers */
SFLPoller *sfl_agent_addPoller(SFLAgent *agent,
			       SFLDataSource_instance *pdsi,
			       void *magic, /* ptr to pass back in getCountersFn() */
			       getCountersFn_t getCountersFn);

/* call this to create receivers */
SFLReceiver *sfl_agent_addReceiver(SFLAgent *agent);

/* random number generator - used by sampler and poller */
uint32_t sfl_random(uint32_t mean);
void sfl_random_init(uint32_t seed);

/* call these functions to GET and SET MIB values */

/* receiver */
uint32_t   sfl_receiver_get_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver);
void        sfl_receiver_set_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver, uint32_t sFlowRcvrMaximumDatagramSize);
/* sampler */
uint32_t sfl_sampler_get_sFlowFsPacketSamplingRate(SFLSampler *sampler);
void      sfl_sampler_set_sFlowFsPacketSamplingRate(SFLSampler *sampler, uint32_t sFlowFsPacketSamplingRate);
/* poller */
uint32_t sfl_poller_get_sFlowCpInterval(SFLPoller *poller);
void      sfl_poller_set_sFlowCpInterval(SFLPoller *poller, uint32_t sFlowCpInterval);

/* call this to indicate a discontinuity with a counter like samplePool so that the
   sflow collector will ignore the next delta */
void sfl_sampler_resetFlowSeqNo(SFLSampler *sampler);

/* call this to indicate a discontinuity with one or more of the counters so that the
   sflow collector will ignore the next delta */
void sfl_poller_resetCountersSeqNo(SFLPoller *poller);

/* You can use this one if you are managing the skip countdown elsewhere */
uint32_t sfl_sampler_next_skip(SFLSampler *sampler);

/* call this once per second (N.B. not on interrupt stack i.e. not hard real-time) */
void sfl_agent_tick(SFLAgent *agent, time_t now);

/* call this with each flow sample */
void sfl_sampler_writeFlowSample(SFLSampler *sampler, SFL_FLOW_SAMPLE_TYPE *fs);

/* call this to push counters samples (usually done in the getCountersFn callback) */
void sfl_poller_writeCountersSample(SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs);

/* call this to deallocate resources */
void sfl_agent_release(SFLAgent *agent);

#endif /* SFLOW_API_H */
