/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* Copyright (c) 2002-2011 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#include "sflow_api.h"

/* internal fns */
static void sfl_receiver_init(SFLReceiver *receiver, SFLAgent *agent);
static void sfl_sampler_init(SFLSampler *sampler, SFLAgent *agent, SFLDataSource_instance *pdsi);
static void sfl_poller_init(SFLPoller *poller, SFLAgent *agent, SFLDataSource_instance *pdsi, void *magic, getCountersFn_t getCountersFn);
static void sfl_receiver_tick(SFLReceiver *receiver, time_t now);
static void sfl_poller_tick(SFLPoller *poller, time_t now);
static int sfl_receiver_writeFlowSample(SFLReceiver *receiver, SFL_FLOW_SAMPLE_TYPE *fs);
static int sfl_receiver_writeCountersSample(SFLReceiver *receiver, SFL_COUNTERS_SAMPLE_TYPE *cs);
static void sfl_agent_error(SFLAgent *agent, char *modName, char *msg);

#define SFL_ALLOC malloc
#define SFL_FREE free

/* ===================================================*/
/* ===================== AGENT =======================*/


static void * sflAlloc(SFLAgent *agent, size_t bytes);
static void sflFree(SFLAgent *agent, void *obj);

/*_________________---------------------------__________________
  _________________       alloc and free      __________________
  -----------------___________________________------------------
*/

static void * sflAlloc(SFLAgent *agent, size_t bytes)
{
    if(agent->allocFn) return (*agent->allocFn)(agent->magic, agent, bytes);
    else return SFL_ALLOC(bytes);
}

static void sflFree(SFLAgent *agent, void *obj)
{
    if(agent->freeFn) (*agent->freeFn)(agent->magic, agent, obj);
    else SFL_FREE(obj);
}
  
/*_________________---------------------------__________________
  _________________       error logging       __________________
  -----------------___________________________------------------
*/
#define MAX_ERRMSG_LEN 1000

static void sfl_agent_error(SFLAgent *agent, char *modName, char *msg)
{
    char errm[MAX_ERRMSG_LEN];
    sprintf(errm, "sfl_agent_error: %s: %s\n", modName, msg);
    if(agent->errorFn) (*agent->errorFn)(agent->magic, agent, errm);
    else {
        fprintf(stderr, "%s\n", errm);
        fflush(stderr);
    }
}

/*________________--------------------------__________________
  ________________    sfl_agent_init        __________________
  ----------------__________________________------------------
*/

void sfl_agent_init(SFLAgent *agent,
                    SFLAddress *myIP, /* IP address of this agent in net byte order */
                    uint32_t subId,   /* agent_sub_id */
                    time_t bootTime,  /* agent boot time */
                    time_t now,       /* time now */
                    void *magic,      /* ptr to pass back in logging and alloc fns */
                    allocFn_t allocFn,
                    freeFn_t freeFn,
                    errorFn_t errorFn,
                    sendFn_t sendFn)
{
    /* first clear everything */
    memset(agent, 0, sizeof(*agent));
    /* now copy in the parameters */
    agent->myIP = *myIP; /* structure copy */
    agent->subId = subId;
    agent->bootTime = bootTime;
    agent->now = now;
    agent->magic = magic;
    agent->allocFn = allocFn;
    agent->freeFn = freeFn;
    agent->errorFn = errorFn;
    agent->sendFn = sendFn;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_release       __________________
  -----------------___________________________------------------
*/

void sfl_agent_release(SFLAgent *agent)
{
 
    SFLSampler *sm;
    SFLPoller *pl;
    SFLReceiver *rcv;
    /* release and free the samplers */
    for(sm = agent->samplers; sm != NULL; ) {
        SFLSampler *nextSm = sm->nxt;
        sflFree(agent, sm);
        sm = nextSm;
    }
    agent->samplers = NULL;

    /* release and free the pollers */
    for( pl= agent->pollers; pl != NULL; ) {
        SFLPoller *nextPl = pl->nxt;
        sflFree(agent, pl);
        pl = nextPl;
    }
    agent->pollers = NULL;

    /* release and free the receivers */
    for( rcv = agent->receivers; rcv != NULL; ) {
        SFLReceiver *nextRcv = rcv->nxt;
        sflFree(agent, rcv);
        rcv = nextRcv;
    }
    agent->receivers = NULL;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_tick          __________________
  -----------------___________________________------------------
*/

void sfl_agent_tick(SFLAgent *agent, time_t now)
{
    SFLReceiver *rcv;
    SFLPoller *pl;

    agent->now = now;
    /* receivers use ticks to flush send data */
    for( rcv = agent->receivers; rcv != NULL; rcv = rcv->nxt) sfl_receiver_tick(rcv, now);
    /* pollers use ticks to decide when to ask for counters */
    for( pl = agent->pollers; pl != NULL; pl = pl->nxt) sfl_poller_tick(pl, now);
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addReceiver   __________________
  -----------------___________________________------------------
*/

SFLReceiver *sfl_agent_addReceiver(SFLAgent *agent)
{
    SFLReceiver *rcv, *r, *prev;

    prev = NULL;
    rcv = (SFLReceiver *)sflAlloc(agent, sizeof(SFLReceiver));
    sfl_receiver_init(rcv, agent);
    /* add to end of list - to preserve the receiver index numbers for existing receivers */
 
    for(r = agent->receivers; r != NULL; prev = r, r = r->nxt);
    if(prev) prev->nxt = rcv;
    else agent->receivers = rcv;
    rcv->nxt = NULL;
    return rcv;
}

/*_________________---------------------------__________________
  _________________     sfl_dsi_compare       __________________
  -----------------___________________________------------------

  Note that if there is a mixture of ds_classes for this agent, then
  the simple numeric comparison may not be correct - the sort order (for
  the purposes of the SNMP MIB) should really be determined by the OID
  that these numeric ds_class numbers are a shorthand for.  For example,
  ds_class == 0 means ifIndex, which is the oid "1.3.6.1.2.1.2.2.1"
*/

static int sfl_dsi_compare(SFLDataSource_instance *pdsi1, SFLDataSource_instance *pdsi2) {
    /* could have used just memcmp(),  but not sure if that would */
    /* give the right answer on little-endian platforms. Safer to be explicit... */
    int cmp = pdsi2->ds_class - pdsi1->ds_class;
    if(cmp == 0) cmp = pdsi2->ds_index - pdsi1->ds_index;
    if(cmp == 0) cmp = pdsi2->ds_instance - pdsi1->ds_instance;
    return cmp;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addSampler    __________________
  -----------------___________________________------------------
*/

SFLSampler *sfl_agent_addSampler(SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    SFLSampler *newsm, *prev, *sm;

    prev = NULL;
    sm = agent->samplers;
    /* keep the list sorted */
    for(; sm != NULL; prev = sm, sm = sm->nxt) {
        int64_t cmp = sfl_dsi_compare(pdsi, &sm->dsi);
        if(cmp == 0) return sm;  /* found - return existing one */
        if(cmp < 0) break;       /* insert here */
    }
    /* either we found the insert point, or reached the end of the list... */
    newsm = (SFLSampler *)sflAlloc(agent, sizeof(SFLSampler));
    sfl_sampler_init(newsm, agent, pdsi);
    if(prev) prev->nxt = newsm;
    else agent->samplers = newsm;
    newsm->nxt = sm;
    return newsm;
}

/*_________________---------------------------__________________
  _________________   sfl_agent_addPoller     __________________
  -----------------___________________________------------------
*/

SFLPoller *sfl_agent_addPoller(SFLAgent *agent,
                               SFLDataSource_instance *pdsi,
                               void *magic,         /* ptr to pass back in getCountersFn() */
                               getCountersFn_t getCountersFn)
{
    SFLPoller *newpl;

    /* keep the list sorted */
    SFLPoller *prev = NULL, *pl = agent->pollers;
    for(; pl != NULL; prev = pl, pl = pl->nxt) {
        int64_t cmp = sfl_dsi_compare(pdsi, &pl->dsi);
        if(cmp == 0) return pl;  /* found - return existing one */
        if(cmp < 0) break;       /* insert here */
    }
    /* either we found the insert point, or reached the end of the list... */
    newpl = (SFLPoller *)sflAlloc(agent, sizeof(SFLPoller));
    sfl_poller_init(newpl, agent, pdsi, magic, getCountersFn);
    if(prev) prev->nxt = newpl;
    else agent->pollers = newpl;
    newpl->nxt = pl;
    return newpl;
}

/* ===================================================*/
/* ===================== SAMPLER =====================*/

/*_________________--------------------------__________________
  _________________   sfl_sampler_init       __________________
  -----------------__________________________------------------
*/

static void sfl_sampler_init(SFLSampler *sampler, SFLAgent *agent, SFLDataSource_instance *pdsi)
{
    /* copy the dsi in case it points to sampler->dsi, which we are about to clear.
       (Thanks to Jagjit Choudray of Force 10 Networks for pointing out this bug) */
    SFLDataSource_instance dsi = *pdsi;

    /* preserve the *nxt pointer too, in case we are resetting this poller and it is
       already part of the agent's linked list (thanks to Matt Woodly for pointing this out) */
    SFLSampler *nxtPtr = sampler->nxt;
  
    /* clear everything */
    memset(sampler, 0, sizeof(*sampler));
  
    /* restore the linked list ptr */
    sampler->nxt = nxtPtr;
  
    /* now copy in the parameters */
    sampler->agent = agent;
    sampler->dsi = dsi;
  
    /* set defaults */
    sfl_sampler_set_sFlowFsPacketSamplingRate(sampler, SFL_DEFAULT_SAMPLING_RATE);
}

/*_________________--------------------------__________________
  _________________       reset              __________________
  -----------------__________________________------------------
*/

uint32_t sfl_sampler_get_sFlowFsPacketSamplingRate(SFLSampler *sampler) {
    return sampler->sFlowFsPacketSamplingRate;
}

void sfl_sampler_set_sFlowFsPacketSamplingRate(SFLSampler *sampler, uint32_t sFlowFsPacketSamplingRate) {
    sampler->sFlowFsPacketSamplingRate = sFlowFsPacketSamplingRate;
    /* initialize the skip count too */
    sampler->skip = sfl_random(sFlowFsPacketSamplingRate);
}

/*_________________---------------------------------__________________
  _________________   sequence number reset         __________________
  -----------------_________________________________------------------
  Used by the agent to indicate a samplePool discontinuity
  so that the sflow collector will know to ignore the next delta.
*/
void sfl_sampler_resetFlowSeqNo(SFLSampler *sampler) { sampler->flowSampleSeqNo = 0; }

/*_________________------------------------------__________________
  _________________ sfl_sampler_writeFlowSample  __________________
  -----------------______________________________------------------
*/

void sfl_sampler_writeFlowSample(SFLSampler *sampler, SFL_FLOW_SAMPLE_TYPE *fs)
{
    if(fs == NULL) return;
    /* increment the sequence number */
    fs->sequence_number = ++sampler->flowSampleSeqNo;
    /* copy the other header fields in */
    fs->source_id = SFL_DS_DATASOURCE(sampler->dsi);
    /* the sampling rate may have been set already. */
    if(fs->sampling_rate == 0) fs->sampling_rate = sampler->sFlowFsPacketSamplingRate;
    /* the samplePool may be maintained upstream too. */
    if( fs->sample_pool == 0) fs->sample_pool = sampler->samplePool;
    /* and the same for the drop event counter */
    if(fs->drops == 0) fs->drops = sampler->dropEvents;
    /* sent to my receiver */
    if(sampler->myReceiver) sfl_receiver_writeFlowSample(sampler->myReceiver, fs);
}

/*_________________---------------------------__________________
  _________________     sfl_random            __________________
  -----------------___________________________------------------
  Gerhard's generator
*/

static uint32_t SFLRandom = 1;

uint32_t sfl_random(uint32_t lim) {
    SFLRandom = ((SFLRandom * 32719) + 3) % 32749;
    return ((SFLRandom % lim) + 1);
} 

void sfl_random_init(uint32_t seed) {
    SFLRandom = seed;
} 

uint32_t sfl_sampler_next_skip(SFLSampler *sampler) {
    return sfl_random((2 * sampler->sFlowFsPacketSamplingRate) - 1);
}



/* ===================================================*/
/* ===================== POLLER ======================*/

/*_________________--------------------------__________________
  _________________    sfl_poller_init       __________________
  -----------------__________________________------------------
*/

static void sfl_poller_init(SFLPoller *poller,
                     SFLAgent *agent,
                     SFLDataSource_instance *pdsi,
                     void *magic,         /* ptr to pass back in getCountersFn() */
                     getCountersFn_t getCountersFn)
{
    /* copy the dsi in case it points to poller->dsi, which we are about to clear */
    SFLDataSource_instance dsi = *pdsi;

    /* preserve the *nxt pointer too, in case we are resetting this poller and it is
       already part of the agent's linked list (thanks to Matt Woodly for pointing this out) */
    SFLPoller *nxtPtr = poller->nxt;

    /* clear everything */
    memset(poller, 0, sizeof(*poller));
  
    /* restore the linked list ptr */
    poller->nxt = nxtPtr;
  
    /* now copy in the parameters */
    poller->agent = agent;
    poller->dsi = dsi; /* structure copy */
    poller->magic = magic;
    poller->getCountersFn = getCountersFn;
}

/*_________________---------------------------__________________
  _________________      MIB access           __________________
  -----------------___________________________------------------
*/

uint32_t sfl_poller_get_sFlowCpInterval(SFLPoller *poller) {
    return (uint32_t)poller->sFlowCpInterval;
}

void sfl_poller_set_sFlowCpInterval(SFLPoller *poller, uint32_t sFlowCpInterval) {
    poller->sFlowCpInterval = sFlowCpInterval;
    /* Set the countersCountdown to be a randomly selected value between 1 and
       sFlowCpInterval. That way the counter polling would be desynchronised even
       if everything came up at the same instant. */
    poller->countersCountdown = sfl_random(sFlowCpInterval);
}

/*_________________---------------------------------__________________
  _________________   sequence number reset         __________________
  -----------------_________________________________------------------
  Used to indicate a counter discontinuity
  so that the sflow collector will know to ignore the next delta.
*/
void sfl_poller_resetCountersSeqNo(SFLPoller *poller) {  poller->countersSampleSeqNo = 0; }

/*_________________---------------------------__________________
  _________________    sfl_poller_tick        __________________
  -----------------___________________________------------------
*/

static void sfl_poller_tick(SFLPoller *poller, time_t now)
{
    if(poller->countersCountdown == 0) return; /* counters retrieval was not enabled */

    if(--poller->countersCountdown == 0) {
        if(poller->getCountersFn != NULL) {
            /* call out for counters */
            SFL_COUNTERS_SAMPLE_TYPE cs;
            memset(&cs, 0, sizeof(cs));
            poller->getCountersFn(poller->magic, poller, &cs);
            /* this countersFn is expected to fill in some counter block elements */
            /* and then call sfl_poller_writeCountersSample(poller, &cs); */
        }
        /* reset the countdown */
        poller->countersCountdown = poller->sFlowCpInterval;
    }
}

/*_________________---------------------------------__________________
  _________________ sfl_poller_writeCountersSample  __________________
  -----------------_________________________________------------------
*/

void sfl_poller_writeCountersSample(SFLPoller *poller, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    /* fill in the rest of the header fields, and send to the receiver */
    cs->sequence_number = ++poller->countersSampleSeqNo;
    cs->source_id = SFL_DS_DATASOURCE(poller->dsi);
    /* sent to my receiver */
    if(poller->myReceiver) sfl_receiver_writeCountersSample(poller->myReceiver, cs);
}





/* ===================================================*/
/* ===================== RECEIVER ====================*/

static void resetSampleCollector(SFLReceiver *receiver);
static void sendSample(SFLReceiver *receiver);
static void receiverError(SFLReceiver *receiver, char *errm);
static void putNet32(SFLReceiver *receiver, uint32_t val);
static void putAddress(SFLReceiver *receiver, SFLAddress *addr);

/*_________________--------------------------__________________
  _________________    sfl_receiver_init     __________________
  -----------------__________________________------------------
*/

static void sfl_receiver_init(SFLReceiver *receiver, SFLAgent *agent)
{
    /* first clear everything */
    memset(receiver, 0, sizeof(*receiver));

    /* now copy in the parameters */
    receiver->agent = agent;

    /* set defaults */
    receiver->sFlowRcvrMaximumDatagramSize = SFL_DEFAULT_DATAGRAM_SIZE;


    /* prepare to receive the first sample */
    resetSampleCollector(receiver);
}

/*_________________----------------------------------------_____________
  _________________          MIB Vars                      _____________
  -----------------________________________________________-------------
*/
uint32_t sfl_receiver_get_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver) {
    return receiver->sFlowRcvrMaximumDatagramSize;
}
void sfl_receiver_set_sFlowRcvrMaximumDatagramSize(SFLReceiver *receiver, uint32_t sFlowRcvrMaximumDatagramSize) {
    uint32_t mdz = sFlowRcvrMaximumDatagramSize;
    if(mdz < SFL_MIN_DATAGRAM_SIZE) mdz = SFL_MIN_DATAGRAM_SIZE;
    receiver->sFlowRcvrMaximumDatagramSize = mdz;
}

/*_________________---------------------------__________________
  _________________   sfl_receiver_tick       __________________
  -----------------___________________________------------------
*/

static void sfl_receiver_tick(SFLReceiver *receiver, time_t now)
{
    /* if there are any samples to send, flush them now */
    if(receiver->sampleCollector.numSamples > 0) sendSample(receiver);
}

/*_________________-----------------------------__________________
  _________________   receiver write utilities  __________________
  -----------------_____________________________------------------
*/
 
static void put32(SFLReceiver *receiver, uint32_t val)
{
    *receiver->sampleCollector.datap++ = val;
}

static void putNet32(SFLReceiver *receiver, uint32_t val)
{
    *receiver->sampleCollector.datap++ = htonl(val);
}

static void putNet64(SFLReceiver *receiver, uint64_t val64)
{
    uint32_t *firstQuadPtr = receiver->sampleCollector.datap;
    /* first copy the bytes in */
    memcpy((u_char *)firstQuadPtr, &val64, 8);
    if(htonl(1) != 1) {
        /* swap the bytes, and reverse the quads too */
        uint32_t tmp = *receiver->sampleCollector.datap++;
        *firstQuadPtr = htonl(*receiver->sampleCollector.datap);
        *receiver->sampleCollector.datap++ = htonl(tmp);
    }
    else receiver->sampleCollector.datap += 2;
}

static void put128(SFLReceiver *receiver, u_char *val)
{
    memcpy(receiver->sampleCollector.datap, val, 16);
    receiver->sampleCollector.datap += 4;
}

static void putString(SFLReceiver *receiver, SFLString *s)
{
    putNet32(receiver, s->len);
    memcpy(receiver->sampleCollector.datap, s->str, s->len);
    receiver->sampleCollector.datap += (s->len + 3) / 4; /* pad to 4-byte boundary */
}

static uint32_t stringEncodingLength(SFLString *s) {
    /* answer in bytes,  so remember to mulitply by 4 after rounding up to nearest 4-byte boundary */
    return 4 + (((s->len + 3) / 4) * 4);
}

static void putAddress(SFLReceiver *receiver, SFLAddress *addr)
{
    /* encode unspecified addresses as IPV4:0.0.0.0 - or should we flag this as an error? */
    if(addr->type == 0) {
        putNet32(receiver, SFLADDRESSTYPE_IP_V4);
        put32(receiver, 0);
    }
    else {
        putNet32(receiver, addr->type);
        if(addr->type == SFLADDRESSTYPE_IP_V4) put32(receiver, addr->address.ip_v4.addr);
        else put128(receiver, addr->address.ip_v6.addr);
    }
}

static uint32_t memcacheOpEncodingLength(SFLSampled_memcache *mcop) {
    uint32_t elemSiz = stringEncodingLength(&mcop->key);
    elemSiz += 24; /* protocol, cmd, nkeys, value_bytes, duration_uS, status */
    return elemSiz;
}

static void putSocket4(SFLReceiver *receiver, SFLExtended_socket_ipv4 *socket4) {
    putNet32(receiver, socket4->protocol);
    put32(receiver, socket4->local_ip.addr);
    put32(receiver, socket4->remote_ip.addr);
    putNet32(receiver, socket4->local_port);
    putNet32(receiver, socket4->remote_port);
}

static void putSocket6(SFLReceiver *receiver, SFLExtended_socket_ipv6 *socket6) {
    putNet32(receiver, socket6->protocol);
    put128(receiver, socket6->local_ip.addr);
    put128(receiver, socket6->remote_ip.addr);
    putNet32(receiver, socket6->local_port);
    putNet32(receiver, socket6->remote_port);
}


/*_________________-----------------------------__________________
  _________________      computeFlowSampleSize  __________________
  -----------------_____________________________------------------
*/

static int computeFlowSampleSize(SFLReceiver *receiver, SFL_FLOW_SAMPLE_TYPE *fs)
{
    SFLFlow_sample_element *elem;
    uint32_t elemSiz;
    uint32_t siz = 40; /* tag, length, sequence_number, source_id, sampling_rate,
                          sample_pool, drops, input, output, number of elements */

    /* hard code the wire-encoding sizes, in case the structures are expanded to be 64-bit aligned */

    fs->num_elements = 0; /* we're going to count them again even if this was set by the client */
    for(elem = fs->elements; elem != NULL; elem = elem->nxt) {
        fs->num_elements++;
        siz += 8; /* tag, length */
        elemSiz = 0;
        switch(elem->tag) {
        case SFLFLOW_MEMCACHE: elemSiz = memcacheOpEncodingLength(&elem->flowType.memcache);  break;
        case SFLFLOW_EX_SOCKET4: elemSiz = XDRSIZ_SFLEXTENDED_SOCKET4;  break;
        case SFLFLOW_EX_SOCKET6: elemSiz = XDRSIZ_SFLEXTENDED_SOCKET6;  break;
        default:
            {
                char errm[128];
                sprintf(errm, "computeFlowSampleSize(): unexpected tag (%u)", elem->tag);
                receiverError(receiver, errm);
                return -1;
            }
            break;
        }
        /* cache the element size, and accumulate it into the overall FlowSample size */
        elem->length = elemSiz;
        siz += elemSiz;
    }

    return siz;
}

/*_________________-------------------------------__________________
  _________________ sfl_receiver_writeFlowSample  __________________
  -----------------_______________________________------------------
*/

static int sfl_receiver_writeFlowSample(SFLReceiver *receiver, SFL_FLOW_SAMPLE_TYPE *fs)
{
    int packedSize;
    SFLFlow_sample_element *elem;
    uint32_t encodingSize;

    if(fs == NULL) return -1;
    if((packedSize = computeFlowSampleSize(receiver, fs)) == -1) return -1;

    /* check in case this one sample alone is too big for the datagram */
    if(packedSize > (int)(receiver->sFlowRcvrMaximumDatagramSize - 32)) {
        receiverError(receiver, "flow sample too big for datagram");
        return -1;
    }

    /* if the sample pkt is full enough so that this sample might put */
    /* it over the limit, then we should send it now before going on. */
    if((receiver->sampleCollector.pktlen + packedSize) >= receiver->sFlowRcvrMaximumDatagramSize)
        sendSample(receiver);
    
    receiver->sampleCollector.numSamples++;

    putNet32(receiver, SFLFLOW_SAMPLE);
    putNet32(receiver, packedSize - 8); /* don't include tag and len */
    putNet32(receiver, fs->sequence_number);
    putNet32(receiver, fs->source_id);
    putNet32(receiver, fs->sampling_rate);
    putNet32(receiver, fs->sample_pool);
    putNet32(receiver, fs->drops);
    putNet32(receiver, fs->input);
    putNet32(receiver, fs->output);
    putNet32(receiver, fs->num_elements);

    for(elem = fs->elements; elem != NULL; elem = elem->nxt) {

        putNet32(receiver, elem->tag);
        putNet32(receiver, elem->length); /* length cached in computeFlowSampleSize() */

        switch(elem->tag) {
        case SFLFLOW_EX_SOCKET4: putSocket4(receiver, &elem->flowType.socket4); break;
        case SFLFLOW_EX_SOCKET6: putSocket6(receiver, &elem->flowType.socket6); break;
        case SFLFLOW_MEMCACHE:
            putNet32(receiver, elem->flowType.memcache.protocol);
            putNet32(receiver, elem->flowType.memcache.command);
            putString(receiver, &elem->flowType.memcache.key);
            putNet32(receiver, elem->flowType.memcache.nkeys);
            putNet32(receiver, elem->flowType.memcache.value_bytes);
            putNet32(receiver, elem->flowType.memcache.duration_uS);
            putNet32(receiver, elem->flowType.memcache.status);
            break;
        default:
            {
                char errm[128];
                sprintf(errm, "sfl_receiver_writeFlowSample: unexpected tag (%u)", elem->tag);
                receiverError(receiver, errm);
                return -1;
            }
            break;
        }
    }

    /* sanity check */
    encodingSize = (u_char *)receiver->sampleCollector.datap
        - (u_char *)receiver->sampleCollector.data
        - receiver->sampleCollector.pktlen;

    if(encodingSize != (uint32_t)packedSize) {
        char errm[128];
        sprintf(errm, "sfl_receiver_writeFlowSample: encoding_size(%u) != expected_size(%u)",
                encodingSize,
                packedSize);
        receiverError(receiver, errm);
        return -1;
    }
      
    /* update the pktlen */
    receiver->sampleCollector.pktlen = (u_char *)receiver->sampleCollector.datap - (u_char *)receiver->sampleCollector.data;
    return packedSize;
}

/*_________________-----------------------------__________________
  _________________ computeCountersSampleSize   __________________
  -----------------_____________________________------------------
*/

static int computeCountersSampleSize(SFLReceiver *receiver, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    SFLCounters_sample_element *elem;
    uint32_t elemSiz;

    uint32_t siz = 20; /* tag, length, sequence_number, source_id, number of elements */
    cs->num_elements = 0; /* we're going to count them again even if this was set by the client */
    for( elem = cs->elements; elem != NULL; elem = elem->nxt) {
        cs->num_elements++;
        siz += 8; /* tag, length */
        elemSiz = 0;

        /* hard code the wire-encoding sizes rather than use sizeof() -- in case the
           structures are expanded to be 64-bit aligned */

        switch(elem->tag) {
        case SFLCOUNTERS_MEMCACHE: elemSiz = XDRSIZ_SFLMEMCACHE_COUNTERS /*sizeof(elem->counterBlock.memcache)*/;  break;
        default:
            {
                char errm[128];
                sprintf(errm, "computeCounterSampleSize(): unexpected counters tag (%u)", elem->tag);
                receiverError(receiver, errm);
                return -1;
            }
            break;
        }
        /* cache the element size, and accumulate it into the overall FlowSample size */
        elem->length = elemSiz;
        siz += elemSiz;
    }
    return siz;
}

/*_________________----------------------------------__________________
  _________________ sfl_receiver_writeCountersSample __________________
  -----------------__________________________________------------------
*/

static int sfl_receiver_writeCountersSample(SFLReceiver *receiver, SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    int packedSize;
    SFLCounters_sample_element *elem;
    uint32_t encodingSize;

    if(cs == NULL) return -1;
    /* if the sample pkt is full enough so that this sample might put */
    /* it over the limit, then we should send it now. */
    if((packedSize = computeCountersSampleSize(receiver, cs)) == -1) return -1;
  
    /* check in case this one sample alone is too big for the datagram */
    /* in fact - if it is even half as big then we should ditch it. Very */
    /* important to avoid overruning the packet buffer. */
    if(packedSize > (int)(receiver->sFlowRcvrMaximumDatagramSize / 2)) {
        receiverError(receiver, "counters sample too big for datagram");
        return -1;
    }
  
    if((receiver->sampleCollector.pktlen + packedSize) >= receiver->sFlowRcvrMaximumDatagramSize)
        sendSample(receiver);
  
    receiver->sampleCollector.numSamples++;
  
    putNet32(receiver, SFLCOUNTERS_SAMPLE);
    putNet32(receiver, packedSize - 8); /* tag and length not included */
    putNet32(receiver, cs->sequence_number);
    putNet32(receiver, cs->source_id);
    putNet32(receiver, cs->num_elements);
  
    for(elem = cs->elements; elem != NULL; elem = elem->nxt) {
    
        putNet32(receiver, elem->tag);
        putNet32(receiver, elem->length); /* length cached in computeCountersSampleSize() */
    
        switch(elem->tag) {
        case SFLCOUNTERS_MEMCACHE:
            putNet32(receiver, elem->counterBlock.memcache.uptime);
            putNet32(receiver, elem->counterBlock.memcache.rusage_user);
            putNet32(receiver, elem->counterBlock.memcache.rusage_system);
            putNet32(receiver, elem->counterBlock.memcache.curr_connections);
            putNet32(receiver, elem->counterBlock.memcache.total_connections);
            putNet32(receiver, elem->counterBlock.memcache.connection_structures);
            putNet32(receiver, elem->counterBlock.memcache.cmd_get);
            putNet32(receiver, elem->counterBlock.memcache.cmd_set);
            putNet32(receiver, elem->counterBlock.memcache.cmd_flush);
            putNet32(receiver, elem->counterBlock.memcache.get_hits);
            putNet32(receiver, elem->counterBlock.memcache.get_misses);
            putNet32(receiver, elem->counterBlock.memcache.delete_misses);
            putNet32(receiver, elem->counterBlock.memcache.delete_hits);
            putNet32(receiver, elem->counterBlock.memcache.incr_misses);
            putNet32(receiver, elem->counterBlock.memcache.incr_hits);
            putNet32(receiver, elem->counterBlock.memcache.decr_misses);
            putNet32(receiver, elem->counterBlock.memcache.decr_hits);
            putNet32(receiver, elem->counterBlock.memcache.cas_misses);
            putNet32(receiver, elem->counterBlock.memcache.cas_hits);
            putNet32(receiver, elem->counterBlock.memcache.cas_badval);
            putNet32(receiver, elem->counterBlock.memcache.auth_cmds);
            putNet32(receiver, elem->counterBlock.memcache.auth_errors);
            putNet64(receiver, elem->counterBlock.memcache.bytes_read);
            putNet64(receiver, elem->counterBlock.memcache.bytes_written);
            putNet32(receiver, elem->counterBlock.memcache.limit_maxbytes);
            putNet32(receiver, elem->counterBlock.memcache.accepting_conns);
            putNet32(receiver, elem->counterBlock.memcache.listen_disabled_num);
            putNet32(receiver, elem->counterBlock.memcache.threads);
            putNet32(receiver, elem->counterBlock.memcache.conn_yields);
            putNet64(receiver, elem->counterBlock.memcache.bytes);
            putNet32(receiver, elem->counterBlock.memcache.curr_items);
            putNet32(receiver, elem->counterBlock.memcache.total_items);
            putNet32(receiver, elem->counterBlock.memcache.evictions);
            break;
        default:
            {
                char errm[128];
                sprintf(errm, "unexpected counters tag (%u)", elem->tag);
                receiverError(receiver, errm);
                return -1;
            }
            break;
        }
    }
    /* sanity check */
    encodingSize = (u_char *)receiver->sampleCollector.datap
        - (u_char *)receiver->sampleCollector.data
        - receiver->sampleCollector.pktlen;
    if(encodingSize != (uint32_t)packedSize) {
        char errm[128];
        sprintf(errm, "sfl_receiver_writeCountersSample: encoding_size(%u) != expected_size(%u)",
                encodingSize,
                packedSize);
        receiverError(receiver, errm);
        return -1;
    }

    /* update the pktlen */
    receiver->sampleCollector.pktlen = (u_char *)receiver->sampleCollector.datap - (u_char *)receiver->sampleCollector.data;
    return packedSize;
}

/*_________________---------------------------__________________
  _________________     sendSample            __________________
  -----------------___________________________------------------
*/

static void sendSample(SFLReceiver *receiver)
{  
    /* construct and send out the sample, then reset for the next one... */
    SFLAgent *agent = receiver->agent;
  
    /* go back and fill in the header */
    receiver->sampleCollector.datap = receiver->sampleCollector.data;
    putNet32(receiver, SFLDATAGRAM_VERSION5);
    putAddress(receiver, &agent->myIP);
    putNet32(receiver, agent->subId);
    putNet32(receiver, ++receiver->sampleCollector.packetSeqNo);
    putNet32(receiver,  (uint32_t)((agent->now - agent->bootTime) * 1000));
    putNet32(receiver, receiver->sampleCollector.numSamples);
  
    /* send */
    if(agent->sendFn) (*agent->sendFn)(agent->magic,
                                       agent,
                                       receiver,
                                       (u_char *)receiver->sampleCollector.data, 
                                       receiver->sampleCollector.pktlen);

    /* reset for the next time */
    resetSampleCollector(receiver);
}

/*_________________---------------------------__________________
  _________________   resetSampleCollector    __________________
  -----------------___________________________------------------
*/

static void resetSampleCollector(SFLReceiver *receiver)
{
    receiver->sampleCollector.pktlen = 0;
    receiver->sampleCollector.numSamples = 0;

    /* clear the buffer completely (ensures that pad bytes will always be zeros - thank you CW) */
    memset((u_char *)receiver->sampleCollector.data, 0, (SFL_SAMPLECOLLECTOR_DATA_QUADS * 4));

    /* point the datap to just after the header */
    receiver->sampleCollector.datap = (receiver->agent->myIP.type == SFLADDRESSTYPE_IP_V6) ?
        (receiver->sampleCollector.data + 10) :
        (receiver->sampleCollector.data + 7);

    /* start pktlen with the right value */
    receiver->sampleCollector.pktlen = (u_char *)receiver->sampleCollector.datap - (u_char *)receiver->sampleCollector.data;
}

/*_________________---------------------------__________________
  _________________    receiverError          __________________
  -----------------___________________________------------------
*/

static void receiverError(SFLReceiver *receiver, char *msg)
{
    sfl_agent_error(receiver->agent, "receiver", msg);
    resetSampleCollector(receiver);
}


