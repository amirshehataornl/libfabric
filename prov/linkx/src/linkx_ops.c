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
#include "shared/ofi_str.h"
#include "ofi_prov.h"
#include "ofi_perf.h"
#include "ofi_hmem.h"
#include "ofi_lock.h"
#include "rdma/fi_ext.h"
#include "linkx.h"

#define LNX_MSG_STARTED 1

int lnx_get_msg(struct fid_peer_srx *srx, fi_addr_t addr,
		size_t size, struct fi_peer_rx_entry **entry)
{
	return -FI_ENOSYS;
}

int lnx_queue_msg(struct fi_peer_rx_entry *entry)
{
	return -FI_ENOSYS;
}

int lnx_queue_tag(struct fi_peer_rx_entry *entry)
{
	/* this is a no-op function. Since in lnx_get_tag() we're already
	 * queuing an entry on the unexpected queue when it needs to, there is
	 * no sense in breaking this procedure into multiple steps. Just gets
	 * confusing
	 */
	return 0;
}

void lnx_free_entry(struct fi_peer_rx_entry *entry)
{
	struct lnx_rx_entry *rx_entry = (struct lnx_rx_entry *) entry;

	ofi_spin_lock(&rx_entry->rx_cep->lpe_fslock);
	ofi_freestack_push(rx_entry->rx_cep->lpe_recv_fs, rx_entry);
	ofi_spin_unlock(&rx_entry->rx_cep->lpe_fslock);
}

static void
lnx_init_rx_entry(struct lnx_rx_entry *entry, struct iovec *iov, void **desc,
			size_t count, fi_addr_t addr, uint64_t tag,
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
}

static struct lnx_rx_entry *
get_rx_entry(struct local_prov_ep *cep, struct iovec *iov, void **desc,
			 size_t count, fi_addr_t addr, uint64_t tag,
			 uint64_t ignore, void *context, uint64_t flags)
{
	struct lnx_rx_entry *rx_entry = NULL;

	ofi_spin_lock(&cep->lpe_fslock);
	if (!ofi_freestack_isempty(cep->lpe_recv_fs))
		rx_entry = ofi_freestack_pop(cep->lpe_recv_fs);
	ofi_spin_unlock(&cep->lpe_fslock);
	if (rx_entry) {
		rx_entry->rx_cep = cep;
		lnx_init_rx_entry(rx_entry, iov, desc, count, addr, tag,
						  ignore, context, flags);
	}

	return rx_entry;
}

int lnx_get_tag(struct fid_peer_srx *srx, fi_addr_t addr,
		uint64_t tag, struct fi_peer_rx_entry **entry)
{
	struct lnx_match_attr match_attr;
	struct lnx_peer_srq *lnx_srq;
	struct local_prov_ep *cep;
	struct lnx_ep *lep;
	struct lnx_rx_entry *rx_entry;
	int rc = 0;

	/* get the endpoint */
	cep = container_of(srx, struct local_prov_ep, lpe_srx);
	lep = cep->lpe_srx.ep_fid.fid.context;
	lnx_srq = &lep->le_srq;

	/* The fi_addr_t is a generic address returned by the provider. It's usually
	 * just an index or id in their AV table. When I get it here, I could have
	 * duplicates if multiple providers are using the same scheme to
	 * insert in the AV table. I need to be able to identify the provider
	 * in this function so I'm able to correctly match this message to
	 * a possible rx entry on my receive queue. That's why we need to make
	 * sure we use the core endpoint as part of the matching key.
	 */
	match_attr.lm_id = addr;
	match_attr.lm_ignore = 0;
	match_attr.lm_tag = tag;
	match_attr.lm_cep = cep;

	/*  1. Find a matching request to the message received.
	 *  2. Return the receive request.
	 *  3. If there are no matching requests, then create a new one
	 *     and return it to the core provider. The core provider will turn
	 *     around and tell us to queue it. Return -FI_ENOENT.
	 *     I'll however insert it here, because there is no sense in doing
	 *     this in two stages.
	 */
	ofi_spin_lock(&lnx_srq->lps_trecv.lqp_qlock);
	rx_entry = (struct lnx_rx_entry *) dlist_remove_first_match(
						&lnx_srq->lps_trecv.lqp_recvq,
						lnx_srq->lps_trecv.match_func,
						&match_attr);
	if (rx_entry)
		goto out;

	rx_entry = get_rx_entry(cep, NULL, NULL, 0, addr, tag, 0, NULL,
							lnx_ep_rx_flags(lep));
	if (!rx_entry) {
		rc = -FI_ENOMEM;
		goto out;
	}

	dlist_insert_tail((struct dlist_entry *)(&rx_entry->rx_entry),
						&lnx_srq->lps_trecv.lqp_unexq);

	rc = -FI_ENOENT;

out:
	ofi_spin_unlock(&lnx_srq->lps_trecv.lqp_qlock);
	*entry = &rx_entry->rx_entry;
	return rc;
}

static int lnx_process_tag(struct lnx_ep *lep, struct local_prov_ep *core,
			struct iovec *iov, void **desc, size_t count, struct lnx_peer *lp,
			fi_addr_t addr, uint64_t tag, uint64_t ignore, void *context,
			uint64_t flags)
{
	struct lnx_peer_srq *lnx_srq = &lep->le_srq;
	struct local_prov_ep *cep = core;
	struct lnx_rx_entry *rx_entry;
	struct lnx_match_attr match_attr;
	int rc = 0;

	match_attr.lm_id = FI_ADDR_UNSPEC;
	match_attr.lm_ignore = ignore;
	match_attr.lm_tag = tag;
	match_attr.lm_cep = cep;

	if (!lep->le_domain->ld_srx_supported)
		return -FI_ENOSYS;

	ofi_spin_lock(&lnx_srq->lps_trecv.lqp_qlock);
	if (!lp) {
		rx_entry = (struct lnx_rx_entry *) dlist_remove_first_match(
						&lnx_srq->lps_trecv.lqp_unexq,
						lnx_srq->lps_trecv.match_func,
						&match_attr);
		if (!rx_entry)
			goto nomatch;

		cep = rx_entry->rx_cep;
		goto match;
	} else {
		int i, j, k;

		for (i = 0; i < LNX_MAX_LOCAL_EPS; i++) {
			struct lnx_peer_prov *lpp = lp->lp_provs[i];
			if (!lpp)
				continue;

			for (j = 0; j < LNX_MAX_LOCAL_EPS; j++) {
				struct lnx_local2peer_map *lpm = lpp->lpp_map[j];
				if (!lpm)
					continue;

				for (k = 0; k < lpm->addr_count; k++) {
					match_attr.lm_id = lpm->peer_addrs[k];
					rx_entry = (struct lnx_rx_entry *) dlist_remove_first_match(
									&lnx_srq->lps_trecv.lqp_unexq,
									lnx_srq->lps_trecv.match_func,
									&match_attr);
					if (rx_entry) {
						cep = lpm->local_ep;
						goto match;
					}
				}
			}
		}
		goto nomatch;
	}

match:
	if (rx_entry) {
		/* match is found in the unexpected queue. call into the core
		 * provider to complete this message
		 */
		ofi_spin_unlock(&lnx_srq->lps_trecv.lqp_qlock);
		lnx_init_rx_entry(rx_entry, iov, desc, count, addr, tag, ignore,
						  context, lnx_ep_rx_flags(lep));
		cep->lpe_srx.peer_ops->start_tag(&rx_entry->rx_entry);
		return LNX_MSG_STARTED;
	}

nomatch:
	/* nothing on the unexpected queue, then allocate one and put it on
	 * the receive queue
	 */
	/* TODO: Where do we get the cep from?
	 * It only makes sense if we know which core endpoint that the
	 * rx-entry is for. However, for the ADDR_UNSPEC case it could be
	 * matched against any core endpoint.
	 */
	rx_entry = get_rx_entry(cep, iov, desc, count, addr, tag, ignore,
							context, lnx_ep_rx_flags(lep));
	if (!rx_entry) {
		rc = -FI_ENOMEM;
		goto out;
	}

	dlist_insert_tail((struct dlist_entry *)(&rx_entry->rx_entry),
						&lnx_srq->lps_trecv.lqp_recvq);

out:
	ofi_spin_unlock(&lnx_srq->lps_trecv.lqp_qlock);
	return rc;
}

ssize_t lnx_trecv(struct fid_ep *ep, void *buf, size_t len, void *desc,
		fi_addr_t src_addr, uint64_t tag, uint64_t ignore, void *context)
{
	int rc;
	struct lnx_ep *lep;
	struct local_prov_ep *cep = NULL;
	fi_addr_t core_addr = FI_ADDR_UNSPEC;
	struct lnx_peer_table *peer_tbl;
	void *mem_desc;
	struct iovec iov = {.iov_base = buf, .iov_len = len};
	struct lnx_peer *lp;
	struct local_prov *entry;

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);

	peer_tbl = lep->le_peer_tbl;

	/* src_addr is an index into the peer table.
	 * This gets us to a peer. Each peer can be reachable on
	 * multiple endpoints. Each endpoint has its own fi_addr_t which is
	 * core provider specific.
	 *
	 * if lp is NULL, then we're attempting to receive from any peer.
	 *
	 * 1. Let's check our unexpected queue for the tag only. Any address
	 *    will match.
	 * 2. kick off a receive on all core providers, because we don't know
	 *    which one will end up getting the message.
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
	 * If nothing is found on the unexpected messages, then lets trigger
	 * a new receive request. For ADDR_ANY, we'll need to kick off
	 * a receive operation on all the core providers.
	 */
	lp = lnx_get_peer(peer_tbl->lpt_entries, src_addr);

	if (lp) {
		rc = lnx_select_recv_pathway(lp, desc, &cep, &core_addr, &iov, 1, &mem_desc);
		if (rc)
			return rc;
	}

	rc = lnx_process_tag(lep, cep, &iov, &desc, 1, lp, core_addr, tag, ignore,
						 context, 0);
	if (rc == LNX_MSG_STARTED)
		return 0;
	else if (rc)
		return rc;

	if (lp) {
		rc = fi_trecv(cep->lpe_ep, buf, len, mem_desc, core_addr, tag, ignore, context);
		return rc;
	}

	/* trigger a recv on all provider endpoints */
	dlist_foreach_container(&local_prov_table, struct local_prov,
							entry, lpv_entry) {
		int i;

		for (i = 0; i < LNX_MAX_LOCAL_EPS; i++) {
			cep = entry->lpv_prov_eps[i];
			if (!cep)
				continue;
			rc = fi_trecv(cep->lpe_ep, buf, len, mem_desc, core_addr, tag, ignore, context);
			if (rc)
				return rc;
		}
	}

	return 0;
}

ssize_t lnx_trecvv(struct fid_ep *ep, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t src_addr, uint64_t tag, uint64_t ignore,
		void *context)
{
	int rc;
	struct lnx_ep *lep;
	struct local_prov_ep *cep = NULL;
	fi_addr_t core_addr = FI_ADDR_UNSPEC;
	struct lnx_peer_table *peer_tbl;
	void *mem_desc;
	struct lnx_peer *lp;
	struct local_prov *entry;

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);

	peer_tbl = lep->le_peer_tbl;

	lp = lnx_get_peer(peer_tbl->lpt_entries, src_addr);

	if (lp) {
		rc = lnx_select_recv_pathway(lp, *desc, &cep, &core_addr, iov, count, &mem_desc);
		if (rc)
			return rc;
	}

	rc = lnx_process_tag(lep, cep, (struct iovec *)iov, desc, count,
						 lp, core_addr, tag, ignore, context, 0);
	if (rc == LNX_MSG_STARTED)
		return 0;
	else if (rc)
		return rc;

	if (lp) {
		rc = fi_trecvv(cep->lpe_ep, iov, &mem_desc, count, core_addr, tag, ignore, context);
		return rc;
	}

	/* trigger a recv on all provider endpoints */
	dlist_foreach_container(&local_prov_table, struct local_prov,
							entry, lpv_entry) {
		int i;

		for (i = 0; i < LNX_MAX_LOCAL_EPS; i++) {
			cep = entry->lpv_prov_eps[i];
			if (!cep)
				continue;
			rc = fi_trecvv(cep->lpe_ep, iov, &mem_desc, count, core_addr, tag, ignore, context);
			if (rc)
				return rc;
		}
	}

	return 0;
}

ssize_t lnx_trecvmsg(struct fid_ep *ep, const struct fi_msg_tagged *msg,
		uint64_t flags)
{
	int rc;
	struct lnx_ep *lep;
	struct local_prov_ep *cep = NULL;
	fi_addr_t core_addr = FI_ADDR_UNSPEC;
	struct lnx_peer_table *peer_tbl;
	void *mem_desc;
	struct lnx_peer *lp;
	struct local_prov *entry;
	struct fi_msg_tagged core_msg;

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);

	peer_tbl = lep->le_peer_tbl;

	lp = lnx_get_peer(peer_tbl->lpt_entries, msg->addr);
	if (lp) {
		rc = lnx_select_recv_pathway(lp, *msg->desc, &cep, &core_addr,
									 msg->msg_iov, msg->iov_count, &mem_desc);
		if (rc)
			return rc;
	}

	rc = lnx_process_tag(lep, cep, (struct iovec *)msg->msg_iov, msg->desc, msg->iov_count,
						 lp, core_addr, msg->tag, msg->ignore,
						 msg->context, 0);
	if (rc == LNX_MSG_STARTED)
		return 0;
	else if (rc)
		return rc;

	memcpy(&core_msg, msg, sizeof(*msg));

	core_msg.desc = mem_desc;
	core_msg.addr = core_addr;

	if (lp) {
		rc = fi_trecvmsg(cep->lpe_ep, &core_msg, flags);
		return 0;
	}

	/* trigger a recv on all provider endpoints */
	dlist_foreach_container(&local_prov_table, struct local_prov,
							entry, lpv_entry) {
		int i;

		for (i = 0; i < LNX_MAX_LOCAL_EPS; i++) {
			cep = entry->lpv_prov_eps[i];
			if (!cep)
				continue;
			rc = fi_trecvmsg(cep->lpe_ep, &core_msg, flags);
			if (rc)
				return rc;
		}
	}

	return 0;
}

ssize_t lnx_tsend(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		fi_addr_t dest_addr, uint64_t tag, void *context)
{
	int rc;
	struct lnx_ep *lep;
	struct local_prov_ep *cep;
	fi_addr_t core_addr;
	struct lnx_peer_table *peer_tbl;
	void *mem_desc;
	struct iovec iov = {.iov_base = (void*) buf, .iov_len = len};

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);

	peer_tbl = lep->le_peer_tbl;

	rc = lnx_select_send_pathway(peer_tbl->lpt_entries[dest_addr], desc, &cep,
								 &core_addr, &iov, 1, &mem_desc);
	if (rc)
		return rc;

	rc = fi_tsend(cep->lpe_ep, buf, len, mem_desc, core_addr, tag, context);

	return rc;
}

ssize_t lnx_tsendv(struct fid_ep *ep, const struct iovec *iov, void **desc,
		size_t count, fi_addr_t dest_addr, uint64_t tag, void *context)
{
	int rc;
	struct lnx_ep *lep;
	struct local_prov_ep *cep;
	fi_addr_t core_addr;
	struct lnx_peer_table *peer_tbl;
	void *mem_desc;

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);

	peer_tbl = lep->le_peer_tbl;

	rc = lnx_select_send_pathway(peer_tbl->lpt_entries[dest_addr], *desc, &cep,
								 &core_addr, iov, count, &mem_desc);
	if (rc)
		return rc;

	rc = fi_tsendv(cep->lpe_ep, iov, &mem_desc, count, core_addr, tag, context);

	return rc;
}

ssize_t lnx_tsendmsg(struct fid_ep *ep, const struct fi_msg_tagged *msg,
		uint64_t flags)
{
	int rc;
	struct lnx_ep *lep;
	struct local_prov_ep *cep;
	fi_addr_t core_addr;
	struct lnx_peer_table *peer_tbl;
	void *mem_desc;
	struct fi_msg_tagged core_msg;

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);

	peer_tbl = lep->le_peer_tbl;

	rc = lnx_select_send_pathway(peer_tbl->lpt_entries[msg->addr],
								 *msg->desc, &cep, &core_addr, msg->msg_iov,
								 msg->iov_count, &mem_desc);
	if (rc)
		return rc;

	memcpy(&core_msg, msg, sizeof(*msg));

	core_msg.desc = mem_desc;

	rc = fi_tsendmsg(cep->lpe_ep, &core_msg, flags);

	return rc;
}

ssize_t lnx_tinject(struct fid_ep *ep, const void *buf, size_t len,
		fi_addr_t dest_addr, uint64_t tag)
{
	int rc;
	struct lnx_ep *lep;
	struct local_prov_ep *cep;
	fi_addr_t core_addr;
	struct lnx_peer_table *peer_tbl;

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);

	peer_tbl = lep->le_peer_tbl;

	rc = lnx_select_send_pathway(peer_tbl->lpt_entries[dest_addr], NULL, &cep,
								 &core_addr, NULL, 0, NULL);
	if (rc)
		return rc;

	rc = fi_tinject(cep->lpe_ep, buf, len, core_addr, tag);

	return rc;
}

ssize_t lnx_tsenddata(struct fid_ep *ep, const void *buf, size_t len, void *desc,
		uint64_t data, fi_addr_t dest_addr, uint64_t tag, void *context)
{
	int rc;
	struct lnx_ep *lep;
	struct local_prov_ep *cep;
	fi_addr_t core_addr;
	struct lnx_peer_table *peer_tbl;
	void *mem_desc;
	struct iovec iov = {.iov_base = (void*)buf, .iov_len = len};

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);

	peer_tbl = lep->le_peer_tbl;

	rc = lnx_select_send_pathway(peer_tbl->lpt_entries[dest_addr], desc, &cep,
								 &core_addr, &iov, 1, &mem_desc);
	if (rc)
		return rc;

	rc = fi_tsenddata(cep->lpe_ep, buf, len, mem_desc,
					  data, core_addr, tag, context);

	return rc;
}

ssize_t lnx_tinjectdata(struct fid_ep *ep, const void *buf, size_t len,
		uint64_t data, fi_addr_t dest_addr, uint64_t tag)
{
	int rc;
	struct lnx_ep *lep;
	struct local_prov_ep *cep;
	fi_addr_t core_addr;
	struct lnx_peer_table *peer_tbl;

	lep = container_of(ep, struct lnx_ep, le_ep.ep_fid.fid);

	peer_tbl = lep->le_peer_tbl;

	rc = lnx_select_send_pathway(peer_tbl->lpt_entries[dest_addr], NULL, &cep,
								 &core_addr, NULL, 0, NULL);
	if (rc)
		return rc;

	rc = fi_tinjectdata(cep->lpe_ep, buf, len, data, core_addr, tag);

	return rc;
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
	.read = fi_no_rma_read,
	.readv = fi_no_rma_readv,
	.readmsg = fi_no_rma_readmsg,
	.write = fi_no_rma_write,
	.writev = fi_no_rma_writev,
	.writemsg = fi_no_rma_writemsg,
	.inject = fi_no_rma_inject,
	.writedata = fi_no_rma_writedata,
	.injectdata = fi_no_rma_injectdata,
};

struct fi_ops_atomic lnx_atomic_ops = {
	.size = sizeof(struct fi_ops_atomic),
	.write = fi_no_atomic_write,
	.writev = fi_no_atomic_writev,
	.writemsg = fi_no_atomic_writemsg,
	.inject = fi_no_atomic_inject,
	.readwrite = fi_no_atomic_readwrite,
	.readwritev = fi_no_atomic_readwritev,
	.readwritemsg = fi_no_atomic_readwritemsg,
	.compwrite = fi_no_atomic_compwrite,
	.compwritev = fi_no_atomic_compwritev,
	.compwritemsg = fi_no_atomic_compwritemsg,
	.writevalid = fi_no_atomic_writevalid,
	.readwritevalid = fi_no_atomic_readwritevalid,
	.compwritevalid = fi_no_atomic_compwritevalid,
};


