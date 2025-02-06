/*
 * Copyright (c) 2022 ORNL. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

#include <rdma/fi_errno.h>
#include "ofi_util.h"
#include "ofi.h"
#include "ofi_str.h"
#include "ofi_prov.h"
#include "ofi_perf.h"
#include "ofi_hmem.h"
#include "ofi_lock.h"
#include "rdma/fi_ext.h"
#include "ofi_iov.h"
#include "lnx.h"

int lnx_get_msg(struct fid_peer_srx *srx, struct fi_peer_match_attr *match,
		struct fi_peer_rx_entry **entry)
{
	return -FI_ENOSYS;
}

int lnx_queue_msg(struct fi_peer_rx_entry *entry)
{
	return -FI_ENOSYS;
}

void lnx_free_entry(struct fi_peer_rx_entry *entry)
{
	struct lnx_rx_entry *rx_entry = (struct lnx_rx_entry *) entry;
	ofi_spin_t *bplock;

	if (rx_entry->rx_global)
		bplock = &global_bplock;
	else
		bplock = &rx_entry->rx_lep->le_bplock;

	ofi_spin_lock(bplock);
	ofi_buf_free(rx_entry);
	ofi_spin_unlock(bplock);
}

static void
lnx_init_rx_entry(struct lnx_rx_entry *entry, const struct iovec *iov,
		  void **desc, size_t count, fi_addr_t addr, uint64_t tag,
		  uint64_t ignore, void *context, uint64_t flags)
{
	memcpy(&entry->rx_iov, iov, sizeof(*iov) * count);
	if (desc)
		memcpy(entry->rx_desc, desc, sizeof(*desc) * count);

	entry->rx_entry.iov = entry->rx_iov;
	entry->rx_entry.desc = entry->rx_desc;
	entry->rx_entry.count = count;
	entry->rx_entry.addr = addr;
	entry->rx_entry.context = context;
	entry->rx_entry.tag = tag;
	entry->rx_entry.flags = flags;
	entry->rx_ignore = ignore;
}

static struct lnx_rx_entry *
get_rx_entry(struct lnx_ep *lep, const struct iovec *iov,
	     void **desc, size_t count, fi_addr_t addr,
	     uint64_t tag, uint64_t ignore, void *context,
	     uint64_t flags)
{
	struct lnx_rx_entry *rx_entry = NULL;
	ofi_spin_t *bplock;
	struct ofi_bufpool *bp;

	/* if lp is NULL, then we don't know where the message is going to
	 * come from, so allocate the rx_entry from a global pool
	 */
	if (!lep) {
		bp = global_recv_bp;
		bplock = &global_bplock;
	} else {
		bp = lep->le_recv_bp;
		bplock = &lep->le_bplock;
	}

	ofi_spin_lock(bplock);
	rx_entry = (struct lnx_rx_entry *)ofi_buf_alloc(bp);
	ofi_spin_unlock(bplock);
	if (rx_entry) {
		memset(rx_entry, 0, sizeof(*rx_entry));
		if (!lep)
			rx_entry->rx_global = true;
		rx_entry->rx_lep = lep;
		lnx_init_rx_entry(rx_entry, iov, desc, count, addr, tag,
				  ignore, context, flags);
	}

	return rx_entry;
}

static inline struct lnx_rx_entry *
lnx_remove_first_match(struct lnx_queue *q, struct lnx_match_attr *match)
{
	struct lnx_rx_entry *rx_entry;

	ofi_spin_lock(&q->lq_qlock);
	rx_entry = (struct lnx_rx_entry *) dlist_remove_first_match(
			&q->lq_queue, q->lq_match_func, match);
	ofi_spin_unlock(&q->lq_qlock);

	return rx_entry;
}

static inline void
lnx_insert_rx_entry(struct lnx_queue *q, struct lnx_rx_entry *entry)
{
	ofi_spin_lock(&q->lq_qlock);
	dlist_insert_tail((struct dlist_entry *)(&entry->rx_entry),
			  &q->lq_queue);
	ofi_spin_unlock(&q->lq_qlock);
}

int lnx_queue_tag(struct fi_peer_rx_entry *entry)
{
	struct lnx_rx_entry *rx_entry = (struct lnx_rx_entry *)entry;
	struct lnx_peer_srq *lnx_srq = (struct lnx_peer_srq*)entry->owner_context;

	FI_DBG(&lnx_prov, FI_LOG_CORE,
		"addr = %lx tag = %lx ignore = 0 found\n",
		entry->addr, entry->tag);

	lnx_insert_rx_entry(&lnx_srq->lps_trecv.lqp_unexq, rx_entry);

	return 0;
}

int lnx_get_tag(struct fid_peer_srx *srx, struct fi_peer_match_attr *match,
		struct fi_peer_rx_entry **entry)
{
	struct lnx_match_attr match_attr = {0};
	struct lnx_peer_srq *lnx_srq;
	struct lnx_core_ep *cep;
	struct lnx_ep *lep;
	struct lnx_rx_entry *rx_entry;
	fi_addr_t addr = match->addr;
	uint64_t tag = match->tag;
	int rc = 0;

	/* can use container of */
	cep = srx->ep_fid.fid.context;
	lep = cep->cep_parent;
	lnx_srq = &lep->le_srq;

	match_attr.lm_addr = lnx_decode_primary_id(addr);
	match_attr.lm_tag = tag;

	rx_entry = lnx_remove_first_match(&lnx_srq->lps_trecv.lqp_recvq,
					  &match_attr);
	if (rx_entry) {
		FI_DBG(&lnx_prov, FI_LOG_CORE,
		       "addr = %lx tag = %lx ignore = 0 found\n",
		       match_attr.lm_addr, tag);

		goto assign;
	}

	FI_DBG(&lnx_prov, FI_LOG_CORE,
	       "addr = %lx tag = %lx ignore = 0 not found\n",
	       match_attr.lm_addr, tag);

	rx_entry = get_rx_entry(lep, NULL, NULL, 0, match_attr.lm_addr, tag, 0, NULL,
				lnx_ep_rx_flags(lep));
	if (!rx_entry) {
		rc = -FI_ENOMEM;
		goto out;
	}

	rx_entry->rx_entry.owner_context = lnx_srq;
	rx_entry->rx_cep = cep;

	rc = -FI_ENOENT;

assign:
	rx_entry->rx_entry.msg_size = MIN(rx_entry->rx_entry.msg_size,
				      match->msg_size);
	*entry = &rx_entry->rx_entry;

out:
	return rc;
}

/*
 * if lp is NULL, then we're attempting to receive from any peer so
 * matching the tag is the only thing that matters.
 *
 * if lp != NULL, then we're attempting to receive from a particular
 * peer. This peer can have multiple endpoints serviced by different core
 * providers.
 *
 * Therefore when we check the unexpected queue, we need to check
 * if we received any messages from any of the peer's addresses. If we
 * find one, then we kick the core provider associated with that
 * address to receive the message.
 *
 * If nothing is found on the unexpected messages, then add a receive
 * request on the SRQ; happens in the lnx_process_recv()
 */
static int lnx_process_recv(struct lnx_ep *lep, const struct iovec *iov, void **desc,
			fi_addr_t addr, size_t count, struct lnx_peer *lp, uint64_t tag,
			uint64_t ignore, void *context, uint64_t flags,
			bool tagged)
{
	struct lnx_peer_srq *lnx_srq = &lep->le_srq;
	struct lnx_rx_entry *rx_entry;
	struct lnx_match_attr match_attr;
	struct lnx_core_ep *cep;
	int rc = 0;

	match_attr.lm_addr = addr;
	match_attr.lm_ignore = ignore;
	match_attr.lm_tag = tag;

	rx_entry = lnx_remove_first_match(&lnx_srq->lps_trecv.lqp_unexq,
					  &match_attr);
	if (!rx_entry) {
		FI_DBG(&lnx_prov, FI_LOG_CORE,
		       "addr=%lx tag=%lx ignore=%lx buf=%p len=%lx not found\n",
		       addr, tag, ignore, iov->iov_base, iov->iov_len);

		goto nomatch;
	}

	FI_DBG(&lnx_prov, FI_LOG_CORE,
	       "addr=%lx tag=%lx ignore=%lx buf=%p len=%lx found\n",
	       addr, tag, ignore, iov->iov_base, iov->iov_len);

	/* match is found in the unexpected queue. call into the core
	 * provider to complete this message
	 */
	lnx_init_rx_entry(rx_entry, iov, desc, count, addr, tag, ignore,
			  context, lnx_ep_rx_flags(lep));
	rx_entry->rx_entry.msg_size = MIN(ofi_total_iov_len(iov, count),
				      rx_entry->rx_entry.msg_size);
	cep = rx_entry->rx_cep;
	if (tagged)
		rc = cep->cep_srx.peer_ops->start_tag(&rx_entry->rx_entry);
	else
		rc = cep->cep_srx.peer_ops->start_msg(&rx_entry->rx_entry);

	if (rc == -FI_EINPROGRESS) {
		/* this is telling me that more messages can match the same
		 * rx_entry. So keep it on the queue
		 */
		FI_DBG(&lnx_prov, FI_LOG_CORE,
		       "addr = %lx tag = %lx ignore = %lx start_tag() in progress\n",
		       addr, tag, ignore);

		goto insert_recvq;
	} else if (rc) {
		FI_WARN(&lnx_prov, FI_LOG_CORE, "start tag failed with %d\n", rc);
	}

	FI_DBG(&lnx_prov, FI_LOG_CORE,
	       "addr = %lx tag = %lx ignore = %lx start_tag() success\n",
	       addr, tag, ignore);

	return 0;

nomatch:
	/* nothing on the unexpected queue, then allocate one and put it on
	 * the receive queue
	 */
	rx_entry = get_rx_entry(NULL, iov, desc, count, addr, tag, ignore,
				context, lnx_ep_rx_flags(lep));
	rx_entry->rx_entry.msg_size = ofi_total_iov_len(iov, count);
	if (!rx_entry) {
		rc = -FI_ENOMEM;
		goto out;
	}

insert_recvq:
	lnx_insert_rx_entry(&lnx_srq->lps_trecv.lqp_recvq, rx_entry);

out:
	return rc;
}

static ssize_t
lnx_recv_common(struct fid_ep *ep, const struct iovec *iov, void *desc,
		fi_addr_t src_addr, uint64_t tag, uint64_t ignore,
		void *context, uint64_t flags)
{
	int rc;
	struct lnx_ep *lep;
	struct lnx_peer *lp;

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);
	if (!lep)
		return -FI_ENOSYS;

	/* TODO: desc != NULL is currently not supported */
	assert(desc == NULL);

	lp = lnx_av_lookup_addr(lep->le_lav, src_addr);
	rc = lnx_process_recv(lep, iov, NULL, src_addr, 1, lp, tag, ignore,
			      context, flags, true);

	return rc;
}

ssize_t lnx_trecv(struct fid_ep *ep, void *buf, size_t len, void *desc,
		fi_addr_t src_addr, uint64_t tag, uint64_t ignore, void *context)
{
	const struct iovec iov = {.iov_base = buf, .iov_len = len};

	return lnx_recv_common(ep, &iov, desc, src_addr, tag, ignore, context, 0);
}

ssize_t lnx_trecvv(struct fid_ep *ep, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t src_addr, uint64_t tag, uint64_t ignore,
		void *context)
{
	void *mr_desc;

	if (count == 0) {
		mr_desc = NULL;
	} else if (iov && count == 1) {
		mr_desc = desc ? desc[0] : NULL;
	} else {
		FI_WARN(&lnx_prov, FI_LOG_CORE, "Invalid IOV\n");
		return -FI_EINVAL;
	}

	return lnx_recv_common(ep, iov, mr_desc, src_addr, tag, ignore, context, 0);
}

ssize_t lnx_trecvmsg(struct fid_ep *ep, const struct fi_msg_tagged *msg,
		     uint64_t flags)
{
	void *mr_desc;

	if (msg->iov_count == 0) {
		mr_desc = NULL;
	} else if (msg->msg_iov && msg->iov_count == 1) {
		mr_desc = msg->desc ? msg->desc[0] : NULL;
	} else {
		FI_WARN(&lnx_prov, FI_LOG_CORE, "Invalid IOV\n");
		return -FI_EINVAL;
	}

	return lnx_recv_common(ep, msg->msg_iov, mr_desc, msg->addr,
			       msg->tag, msg->ignore, msg->context, flags);
}

ssize_t lnx_tsend(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		fi_addr_t dest_addr, uint64_t tag, void *context)
{
	int rc;
	struct lnx_ep *lep;
	struct lnx_core_ep *cep;
	fi_addr_t core_addr;

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);
	if (!lep)
		return -FI_ENOSYS;

	rc = lnx_select_send_endpoints(lep, dest_addr, &cep, &core_addr);
	if (rc)
		return rc;

	FI_DBG(&lnx_prov, FI_LOG_CORE,
	       "sending to %lx tag %lx buf %p len %ld\n",
	       core_addr, tag, buf, len);

	rc = fi_tsend(cep->cep_ep, buf, len, NULL, core_addr, tag, context);

	return rc;
}

ssize_t lnx_tsendv(struct fid_ep *ep, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t dest_addr, uint64_t tag, void *context)
{
	int rc;
	struct lnx_ep *lep;
	struct lnx_core_ep *cep;
	fi_addr_t core_addr;

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);
	if (!lep)
		return -FI_ENOSYS;

	rc = lnx_select_send_endpoints(lep, dest_addr, &cep, &core_addr);
	if (rc)
		return rc;

	FI_DBG(&lnx_prov, FI_LOG_CORE,
	       "sending to %lx tag %lx buf %p len %ld\n",
	       core_addr, tag, buf, len);

	rc = fi_tsendv(cep->cep_ep, iov, NULL, count, core_addr, tag, context);

	return rc;
}

ssize_t lnx_tsendmsg(struct fid_ep *ep, const struct fi_msg_tagged *msg,
		uint64_t flags)
{
	int rc;
	struct lnx_ep *lep;
	struct lnx_core_ep *cep;
	struct fi_msg_tagged core_msg;

	memcpy(&core_msg, msg, sizeof(*msg));

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);
	if (!lep)
		return -FI_ENOSYS;

	rc = lnx_select_send_endpoints(lep, core_msg.addr, &cep, &core_msg.addr);
	if (rc)
		return rc;

	FI_DBG(&lnx_prov, FI_LOG_CORE,
	       "sending to %lx tag %lx\n",
	       core_addr, msg->tag);

	rc = fi_tsendmsg(cep->cep_ep, &core_msg, flags);

	return rc;
}

ssize_t lnx_tinject(struct fid_ep *ep, const void *buf, size_t len,
		fi_addr_t dest_addr, uint64_t tag)
{
	int rc;
	struct lnx_ep *lep;
	struct lnx_core_ep *cep;
	fi_addr_t core_addr;

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);
	if (!lep)
		return -FI_ENOSYS;

	rc = lnx_select_send_endpoints(lep, dest_addr, &cep, &core_addr);
	if (rc)
		return rc;

	FI_DBG(&lnx_prov, FI_LOG_CORE,
	       "sending to %lx tag %lx buf %p len %ld\n",
	       core_addr, tag, buf, len);

	rc = fi_tinject(cep->cep_ep, buf, len, core_addr, tag);

	return rc;
}

ssize_t lnx_tsenddata(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		uint64_t data, fi_addr_t dest_addr, uint64_t tag, void *context)
{
	int rc;
	struct lnx_ep *lep;
	struct lnx_core_ep *cep;
	fi_addr_t core_addr;

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);
	if (!lep)
		return -FI_ENOSYS;

	rc = lnx_select_send_endpoints(lep, dest_addr, &cep, &core_addr);
	if (rc)
		return rc;

	FI_DBG(&lnx_prov, FI_LOG_CORE,
	       "sending to %lx tag %lx buf %p len %ld\n",
	       core_addr, tag, buf, len);

	rc = fi_tsenddata(cep->cep_ep, buf, len, NULL,
			  data, core_addr, tag, context);

	return rc;
}

ssize_t lnx_tinjectdata(struct fid_ep *ep, const void *buf, size_t len,
			uint64_t data, fi_addr_t dest_addr, uint64_t tag)
{
	int rc;
	struct lnx_ep *lep;
	struct lnx_core_ep *cep;
	fi_addr_t core_addr;

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);
	if (!lep)
		return -FI_ENOSYS;

	rc = lnx_select_send_endpoints(lep, dest_addr, &cep, &core_addr);
	if (rc)
		return rc;

	FI_DBG(&lnx_prov, FI_LOG_CORE,
	       "sending to %lx tag %lx buf %p len %ld\n",
	       core_addr, tag, buf, len);

	rc = fi_tinjectdata(cep->cep_ep, buf, len, data, core_addr, tag);

	return rc;
}

static inline ssize_t
lnx_rma_read(struct fid_ep *ep, void *buf, size_t len, void *desc,
	fi_addr_t src_addr, uint64_t addr, uint64_t key, void *context)
{
	return -FI_ENOSYS;
}

static inline ssize_t
lnx_rma_write(struct fid_ep *ep, const void *buf, size_t len, void *desc,
	 fi_addr_t dest_addr, uint64_t addr, uint64_t key, void *context)
{
	return -FI_ENOSYS;
}

static inline ssize_t
lnx_atomic_write(struct fid_ep *ep,
	  const void *buf, size_t count, void *desc,
	  fi_addr_t dest_addr,
	  uint64_t addr, uint64_t key,
	  enum fi_datatype datatype, enum fi_op op, void *context)
{
	return -FI_ENOSYS;
}

static inline ssize_t
lnx_atomic_readwrite(struct fid_ep *ep,
		const void *buf, size_t count, void *desc,
		void *result, void *result_desc,
		fi_addr_t dest_addr,
		uint64_t addr, uint64_t key,
		enum fi_datatype datatype, enum fi_op op, void *context)
{
	return -FI_ENOSYS;
}

static inline ssize_t
lnx_atomic_compwrite(struct fid_ep *ep,
		  const void *buf, size_t count, void *desc,
		  const void *compare, void *compare_desc,
		  void *result, void *result_desc,
		  fi_addr_t dest_addr,
		  uint64_t addr, uint64_t key,
		  enum fi_datatype datatype, enum fi_op op, void *context)
{
	return -FI_ENOSYS;
}

struct fi_ops_tagged lnx_tagged_ops = {
	.size = sizeof(struct fi_ops_tagged),
	.recv = lnx_trecv,
	.recvv = lnx_trecvv,
	.recvmsg = lnx_trecvmsg,
	.send = lnx_tsend,
	.sendv = lnx_tsendv,
	.sendmsg = lnx_tsendmsg,
	.inject = lnx_tinject,
	.senddata = lnx_tsenddata,
	.injectdata = lnx_tinjectdata,
};

struct fi_ops_msg lnx_msg_ops = {
	.size = sizeof(struct fi_ops_msg),
	.recv = fi_no_msg_recv,
	.recvv = fi_no_msg_recvv,
	.recvmsg = fi_no_msg_recvmsg,
	.send = fi_no_msg_send,
	.sendv = fi_no_msg_sendv,
	.sendmsg = fi_no_msg_sendmsg,
	.inject = fi_no_msg_inject,
	.senddata = fi_no_msg_senddata,
	.injectdata = fi_no_msg_injectdata,
};

struct fi_ops_rma lnx_rma_ops = {
	.size = sizeof(struct fi_ops_rma),
	.read = lnx_rma_read,
	.readv = fi_no_rma_readv,
	.readmsg = fi_no_rma_readmsg,
	.write = lnx_rma_write,
	.writev = fi_no_rma_writev,
	.writemsg = fi_no_rma_writemsg,
	.inject = fi_no_rma_inject,
	.writedata = fi_no_rma_writedata,
	.injectdata = fi_no_rma_injectdata,
};

struct fi_ops_atomic lnx_atomic_ops = {
	.size = sizeof(struct fi_ops_atomic),
	.write = lnx_atomic_write,
	.writev = fi_no_atomic_writev,
	.writemsg = fi_no_atomic_writemsg,
	.inject = fi_no_atomic_inject,
	.readwrite = lnx_atomic_readwrite,
	.readwritev = fi_no_atomic_readwritev,
	.readwritemsg = fi_no_atomic_readwritemsg,
	.compwrite = lnx_atomic_compwrite,
	.compwritev = fi_no_atomic_compwritev,
	.compwritemsg = fi_no_atomic_compwritemsg,
	.writevalid = fi_no_atomic_writevalid,
	.readwritevalid = fi_no_atomic_readwritevalid,
	.compwritevalid = fi_no_atomic_compwritevalid,
};


