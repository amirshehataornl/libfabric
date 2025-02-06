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
#include "rdma/fi_ext.h"
#include "lnx.h"

extern struct fi_ops_cm lnx_cm_ops;
extern struct fi_ops_msg lnx_msg_ops;
extern struct fi_ops_tagged lnx_tagged_ops;
extern struct fi_ops_rma lnx_rma_ops;
extern struct fi_ops_atomic lnx_atomic_ops;

static struct fi_ops_srx_owner lnx_srx_ops = {
	.size = sizeof(struct fi_ops_srx_owner),
	.get_msg = lnx_get_msg,
	.get_tag = lnx_get_tag,
	.queue_msg = lnx_queue_msg,
	.queue_tag = lnx_queue_tag,
	.free_entry = lnx_free_entry,
	.foreach_unspec_addr = lnx_foreach_unspec_addr,
};

int lnx_ep_close(struct fid *fid)
{
	int rc, frc = FI_SUCCESS;
	struct lnx_ep *lep;
	struct lnx_core_ep *cep;
	struct dlist_entry *tmp;

	lep = container_of(fid, struct lnx_ep, le_ep.ep_fid.fid);

	dlist_foreach_container_safe(&lep->le_core_eps, struct lnx_core_ep,
				     cep, cep_entry, tmp) {
		dlist_remove(&cep->cep_entry);
		rc = fi_close(&cep->cep_ep->fid);
		if (rc)
			frc = rc;
		rc = fi_close(&cep->cep_srx_ep->fid);
		if (rc)
			frc = rc;
		free(cep);
	}

	ofi_endpoint_close(&lep->le_ep);
	ofi_bufpool_destroy(lep->le_recv_bp);
	free(lep);

	return frc;
}

static int lnx_enable_core_eps(struct lnx_ep *lep)
{
	int rc;
	struct lnx_core_domain *cd;
	struct lnx_core_ep *cep;
	struct fi_rx_attr attr = {0};
	struct fi_peer_srx_context peer_srx;

	attr.op_flags = FI_PEER;
	peer_srx.size = sizeof(peer_srx);

	dlist_foreach_container(&lep->le_core_eps, struct lnx_core_ep,
				cep, cep_entry) {
		cd = cep->cep_domain;

		cep->cep_srx.owner_ops = &lnx_srx_ops;
		cep->cep_srx.ep_fid.fid.context = cep;
		peer_srx.srx = &cep->cep_srx;

		rc = fi_srx_context(cd->cd_domain, &attr,
				&cep->cep_srx_ep, &peer_srx);
		if (rc)
			return rc;

		rc = fi_ep_bind(cep->cep_ep,
				&cep->cep_srx_ep->fid, 0);
		if (rc)
			return rc;

		rc = fi_enable(cep->cep_ep);
		if (rc)
			return rc;
	}

	return 0;
}

static int lnx_ep_control(struct fid *fid, int command, void *arg)
{
	struct lnx_ep *lep;
	int rc;

	lep = container_of(fid, struct lnx_ep, le_ep.ep_fid.fid);

	switch (command) {
	case FI_ENABLE:
		if (lep->le_fclass == FI_CLASS_EP &&
		    ((ofi_needs_rx(lep->le_ep.caps) && !lep->le_ep.rx_cq) ||
		    (ofi_needs_tx(lep->le_ep.caps) && !lep->le_ep.tx_cq)))
			return -FI_ENOCQ;
		if (!lep->le_lav)
			return -FI_ENOAV;
		rc = lnx_enable_core_eps(lep);
		break;
	default:
		return -FI_ENOSYS;
	}

	return rc;
}

static int lnx_bind_core_cqs(struct lnx_ep *lep, struct lnx_cq *lcq,
			     uint64_t flags)
{
	int rc;
	struct lnx_core_domain *cd;
	struct lnx_core_cq *core_cq;
	struct lnx_core_ep *cep;

	dlist_foreach_container(&lcq->lcq_core_cqs, struct lnx_core_cq, core_cq,
				cc_entry) {
		cd = core_cq->cc_domain;
		dlist_foreach_container(&lep->le_core_eps, struct lnx_core_ep,
					cep, cep_entry) {
			if (cep->cep_domain != cd)
				continue;
			rc = fi_ep_bind(cep->cep_ep,
					&core_cq->cc_cq->fid, flags);
			if (rc)
				return rc;
		}
	}

	return 0;
}

int lnx_bind_core_avs(struct lnx_ep *lep, struct lnx_av *lav, uint64_t flags)
{
	int rc;
	struct lnx_core_domain *cd;
	struct lnx_core_ep *cep;
	struct lnx_core_av *cav;

	dlist_foreach_container(&lav->lav_core_avs, struct lnx_core_av,
				cav, cav_entry) {
		cd = cav->cav_domain;
		dlist_foreach_container(&lep->le_core_eps, struct lnx_core_ep,
					cep, cep_entry) {
			if (cep->cep_domain != cd)
				continue;
			if (cep->cep_cav)
				return -FI_EALREADY;
			rc = fi_ep_bind(cep->cep_ep, &cav->cav_av->fid, flags);
			if (rc)
				return rc;
			dlist_insert_tail(&cep->cep_av_entry, &cav->cav_ep_list);
			cep->cep_cav = cav;
		}
	}

	return 0;
}

static int
lnx_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	int rc = 0;
	struct lnx_ep *lep;
	struct lnx_cq *lcq;
	struct lnx_av *lav;

	switch (fid->fclass) {
	case FI_CLASS_EP:	/* Standard EP */
	case FI_CLASS_SEP:	/* Scalable EP */
		lep = container_of(fid, struct lnx_ep, le_ep.ep_fid.fid);
		break;

	default:
		return -FI_EINVAL;
	}

	switch (bfid->fclass) {
	case FI_CLASS_EQ:
		return -FI_ENOSYS;

	case FI_CLASS_CQ:
		if (lep->le_lcq) {
			FI_WARN(&lnx_prov, FI_LOG_CORE,
				"CQ already bound\n");
			return -FI_EINVAL;
		}
		lcq = container_of(bfid, struct lnx_cq, lcq_util_cq.cq_fid.fid);
		rc = lnx_bind_core_cqs(lep, lcq, flags);
		if (rc)
			goto out;
		rc = ofi_ep_bind_cq(&lep->le_ep, &lcq->lcq_util_cq, flags);
		if (rc)
			goto out;
		lep->le_lcq = lcq;
		break;

	case FI_CLASS_CNTR:
		return -FI_ENOSYS;

	case FI_CLASS_AV:
		if (lep->le_lav) {
			FI_WARN(&lnx_prov, FI_LOG_CORE,
				"AV already bound\n");
			return -FI_EINVAL;
		}
		lav = container_of(bfid, struct lnx_av, lav_av.av_fid.fid);
		rc = lnx_bind_core_avs(lep, lav, flags);
		if (rc)
			goto out;
		rc = ofi_ep_bind_av(&lep->le_ep, &lav->lav_av);
		if (rc)
			goto out;
		lep->le_lav = lav;
		break;

	case FI_CLASS_STX_CTX:	/* shared TX context */
		return -FI_ENOSYS;

	case FI_CLASS_SRX_CTX:	/* shared RX context */
		return -FI_ENOSYS;

	default:
		return -FI_EINVAL;
	}

out:
	return rc;
}

int lnx_getname(fid_t fid, void *addr, size_t *addrlen)
{
	int rc;
	char hostname[FI_NAME_MAX];
	struct lnx_core_ep *cep;
	struct lnx_ep *lep;
	struct lnx_ep_addr *ep_addr;
	struct lnx_address *lnx_addr;
	char *cep_addr, *prov_name;
	int ep_count = 0;
	size_t size;
	size_t eps_addrlen[256] = {0};

	lep = container_of(fid, struct lnx_ep, le_ep.ep_fid.fid);

	rc = gethostname(hostname, FI_NAME_MAX);
	if (rc == -1) {
		FI_WARN(&lnx_prov, FI_LOG_CORE, "failed to get hostname\n");
		return -FI_EPERM;
	}

	/* calculate the total size required for the address */
	size = sizeof(*lnx_addr);

	dlist_foreach_container(&lep->le_core_eps, struct lnx_core_ep,
				cep, cep_entry) {
		if (ep_count >= 256)
			return -FI_E2BIG;
		eps_addrlen[ep_count] = 0;
		rc = fi_getname(&cep->cep_ep->fid, NULL, &eps_addrlen[ep_count]);
		if (rc == -FI_ETOOSMALL) {
			size += (sizeof(*ep_addr)) + eps_addrlen[ep_count];
		} else {
			return -FI_EINVAL;
		}
		ep_count++;
	}

	if (!addr || *addrlen < size) {
		*addrlen = size;
		return -FI_ETOOSMALL;
	}

	lnx_addr = (struct lnx_address *) addr;
	ep_addr = (struct lnx_ep_addr *)((char*)lnx_addr + sizeof(*lnx_addr));

	memcpy(lnx_addr->la_hostname, hostname, FI_NAME_MAX - 1);
	lnx_addr->la_ep_count = ep_count;

	ep_count = 0;
	dlist_foreach_container(&lep->le_core_eps, struct lnx_core_ep,
				cep, cep_entry) {
		prov_name = cep->cep_domain->cd_info->fabric_attr->name;
		memcpy(ep_addr->lea_prov, prov_name, strlen(prov_name)+1);
		cep_addr = (char*)ep_addr + sizeof(*ep_addr);
		rc = fi_getname(&cep->cep_ep->fid, (void*)cep_addr, &eps_addrlen[ep_count]);
		if (rc)
			return rc;
		ep_addr->lea_addr_size = eps_addrlen[ep_count];
		ep_addr = (struct lnx_ep_addr *) (cep_addr + eps_addrlen[ep_count]);
		ep_count++;
	}

	return 0;
}

static ssize_t lnx_ep_cancel(fid_t fid, void *context)
{
	int rc = 0;
	char *prov_name;
	struct lnx_ep *lep;
	struct lnx_core_ep *cep;

	switch (fid->fclass) {
	case FI_CLASS_EP:
		lep = container_of(fid, struct lnx_ep, le_ep.ep_fid.fid);
		break;
	default:
		return -FI_EINVAL;
	}

	dlist_foreach_container(&lep->le_core_eps,
				struct lnx_core_ep, cep, cep_entry) {
		prov_name = cep->cep_domain->cd_info->domain_attr->name;
		rc = fi_cancel(&cep->cep_ep->fid, context);
		if (rc == -FI_ENOSYS) {
			FI_WARN(&lnx_prov, FI_LOG_CORE,
				"%s: Operation not supported by provider. "
				"Ignoring\n", prov_name);
			rc = 0;
			continue;
		} else if (rc != FI_SUCCESS) {
			return rc;
		}
	}

	return rc;
}

static int lnx_ep_setopt(fid_t fid, int level, int optname, const void *optval,
			  size_t optlen)
{
	struct lnx_ep *lep;
	struct lnx_core_ep *cep;
	int rc;

	lep = container_of(fid, struct lnx_ep, le_ep.ep_fid.fid);

	dlist_foreach_container(&lep->le_core_eps,
				struct lnx_core_ep, cep, cep_entry) {
		rc = fi_setopt(&cep->cep_ep->fid, level, optname,
				optval, optlen);
		if (rc == -FI_ENOSYS) {
			rc = 0;
			continue;
		} else if (rc != FI_SUCCESS) {
			return rc;
		}
	}

	return rc;
}

struct fi_ops_ep lnx_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = lnx_ep_cancel,
	/* can't get opt, because there is no way to report multiple
	 * options for the different links */
	.getopt = fi_no_getopt,
	.setopt = lnx_ep_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = fi_no_rx_size_left,
	.tx_size_left = fi_no_tx_size_left,
};

struct fi_ops lnx_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = lnx_ep_close,
	.bind = lnx_ep_bind,
	.control = lnx_ep_control,
	.ops_open = fi_no_ops_open,
};

struct fi_ops_cm lnx_cm_ops = {
	.size = sizeof(struct fi_ops_cm),
	.setname = fi_no_setname,
	.getname = lnx_getname,
	.getpeer = fi_no_getpeer,
	.connect = fi_no_connect,
	.listen = fi_no_listen,
	.accept = fi_no_accept,
	.reject = fi_no_reject,
	.shutdown = fi_no_shutdown,
};

static int lnx_open_eps(struct dlist_entry *domains, struct fi_info *info,
			void *context, size_t fclass, struct lnx_ep *lep)
{
	int rc = 0;
	bool local;
	struct lnx_core_domain *cd;
	struct lnx_core_ep *cep;
	char *prov_name;

	dlist_foreach_container(domains, struct lnx_core_domain, cd, cd_entry) {
		local = false;
		cep = calloc(sizeof(*cep), 1);
		if (!cep)
			return -FI_ENOMEM;

		dlist_init(&cep->cep_entry);
		dlist_init(&cep->cep_av_entry);
		cep->cep_domain = cd;
		cep->cep_parent = lep;
		prov_name = cd->cd_info->fabric_attr->name;
		if (!strcmp(prov_name, "shm"))
			local = true;

		if (fclass == FI_CLASS_EP) {
			rc = fi_endpoint(cd->cd_domain, cd->cd_fabric->cf_info,
					 &cep->cep_ep, context);
		} else {
			/* update endpoint attributes with whatever is being
			 * passed from the application
			 */
			if (cd->cd_fabric->cf_info && info) {
				cd->cd_fabric->cf_info->ep_attr->tx_ctx_cnt =
					info->ep_attr->tx_ctx_cnt;
				cd->cd_fabric->cf_info->ep_attr->rx_ctx_cnt =
					info->ep_attr->rx_ctx_cnt;
			}

			cep->cep_txc = calloc(info->ep_attr->tx_ctx_cnt,
					sizeof(*cep->cep_txc));
			cep->cep_rxc = calloc(info->ep_attr->rx_ctx_cnt,
					sizeof(*cep->cep_rxc));
			if (!cep->cep_txc || !cep->cep_rxc)
				return -FI_ENOMEM;

			rc = fi_scalable_ep(cd->cd_domain, cd->cd_fabric->cf_info,
					    &cep->cep_ep, context);
		}
		if (rc)
			return rc;

		/* keep the shm endpoint at the beginning of the list, so
		 * that when we form the address in lnx_getname, it's the
		 * first one we put there. For local peers it's the only
		 * address which gets inserted. This protocol simplifies
		 * the fast path, as no special checking is done
		 */
		if (local)
			dlist_insert_head(&cep->cep_entry, &lep->le_core_eps);
		else
			dlist_insert_tail(&cep->cep_entry, &lep->le_core_eps);
	}

	return 0;
}

static void
lnx_ep_nosys_progress(struct util_ep *util_ep)
{
	assert(0);
}

static int lnx_common_match(uint64_t tag, uint64_t match_tag,
			    fi_addr_t recv_addr, fi_addr_t addr,
			    uint64_t ignore)
{
	bool tmatch = ((tag | ignore) == (match_tag | ignore));

	if (recv_addr == FI_ADDR_UNSPEC)
		return tmatch;

	return tmatch && (addr == recv_addr);
}

static int lnx_match_recvq(struct dlist_entry *item, const void *args)
{
	struct lnx_match_attr *attr = (struct lnx_match_attr *) args;
	struct lnx_rx_entry *entry = (struct lnx_rx_entry *) item;

	return lnx_common_match(entry->rx_entry.tag, attr->lm_tag,
				entry->rx_entry.addr, attr->lm_addr,
				entry->rx_ignore);
}

static int lnx_match_unexq(struct dlist_entry *item, const void *args)
{
	struct lnx_match_attr *attr = (struct lnx_match_attr *) args;
	struct lnx_rx_entry *entry = (struct lnx_rx_entry *) item;

	return lnx_common_match(attr->lm_tag, entry->rx_entry.tag,
				attr->lm_addr, entry->rx_entry.addr,
				attr->lm_ignore);
}

static inline int
lnx_init_queue(struct lnx_queue *q, dlist_func_t *match_func)
{
	int rc;

	rc = ofi_spin_init(&q->lq_qlock);
	if (rc)
		return rc;

	dlist_init(&q->lq_queue);

	q->lq_match_func = match_func;

	return 0;
}

static inline int
lnx_init_qpair(struct lnx_qpair *qpair, dlist_func_t *recvq_match_func,
			   dlist_func_t *unexq_match_func)
{
	int rc = 0;

	rc = lnx_init_queue(&qpair->lqp_recvq, recvq_match_func);
	if (rc)
		goto out;
	rc = lnx_init_queue(&qpair->lqp_unexq, unexq_match_func);
	if (rc)
		goto out;

out:
	return rc;
}

static inline int
lnx_init_srq(struct lnx_peer_srq *srq)
{
	int rc;

	rc = lnx_init_qpair(&srq->lps_trecv, lnx_match_recvq, lnx_match_unexq);
	if (rc)
		return rc;
	rc = lnx_init_qpair(&srq->lps_recv, lnx_match_recvq, lnx_match_unexq);
	if (rc)
		return rc;

	return rc;
}

static int
lnx_alloc_endpoint(struct fid_domain *domain, struct fi_info *info,
		   struct lnx_ep **out_ep, void *context, size_t fclass)
{
	int rc;
	struct lnx_ep *lep;
	uint64_t mr_mode;
	struct ofi_bufpool_attr bp_attrs = {0};

	lep = calloc(1, sizeof(*lep));
	if (!lep)
		return -FI_ENOMEM;

	lep->le_fclass = fclass;
	lep->le_ep.ep_fid.fid.fclass = fclass;

	lep->le_ep.ep_fid.fid.ops = &lnx_ep_fi_ops;
	lep->le_ep.ep_fid.ops = &lnx_ep_ops;
	lep->le_ep.ep_fid.cm = &lnx_cm_ops;
	lep->le_ep.ep_fid.msg = &lnx_msg_ops;
	lep->le_ep.ep_fid.tagged = &lnx_tagged_ops;
	lep->le_ep.ep_fid.rma = &lnx_rma_ops;
	lep->le_ep.ep_fid.atomic = &lnx_atomic_ops;
	lep->le_domain = container_of(domain, struct lnx_domain,
				     ld_domain.domain_fid);
	lnx_init_srq(&lep->le_srq);

	ofi_spin_init(&lep->le_bplock);
	/* create a buffer pool for the receive requests */
	bp_attrs.size = sizeof(struct lnx_rx_entry);
	bp_attrs.alignment = 8;
	bp_attrs.max_cnt = UINT16_MAX;
	bp_attrs.chunk_cnt = 64;
	bp_attrs.flags = OFI_BUFPOOL_NO_TRACK;
	rc = ofi_bufpool_create_attr(&bp_attrs, &lep->le_recv_bp);
	if (rc) {
		FI_WARN(&lnx_prov, FI_LOG_FABRIC,
			"Failed to create receive buffer pool");
		return -FI_ENOMEM;
	}
	rc = ofi_spin_init(&lep->le_bplock);
	if (rc)
		goto fail;

	dlist_init(&lep->le_core_eps);

	rc = lnx_open_eps(&lep->le_domain->ld_core_domains,
			  info, context, fclass, lep);
	if (rc) 
		goto fail;

	mr_mode = lnx_util_prov.info->domain_attr->mr_mode;
	lnx_util_prov.info->domain_attr->mr_mode = 0;
	rc = ofi_endpoint_init(domain, (const struct util_prov *)&lnx_util_prov,
			       (struct fi_info *)lnx_util_prov.info, &lep->le_ep,
			       context, lnx_ep_nosys_progress);
	if (rc)
		goto fail;

	lnx_util_prov.info->domain_attr->mr_mode = mr_mode;
	*out_ep = lep;

	return 0;

fail:
	free(lep);
	return rc;
}

int lnx_scalable_ep(struct fid_domain *domain, struct fi_info *info,
		    struct fid_ep **ep, void *context)
{
	int rc;
	struct lnx_ep *my_ep;

	rc = lnx_alloc_endpoint(domain, info, &my_ep, context, FI_CLASS_SEP);
	if (rc)
		return rc;

	*ep = &my_ep->le_ep.ep_fid;

	return 0;
}

int lnx_endpoint(struct fid_domain *domain, struct fi_info *info,
		 struct fid_ep **ep, void *context)
{
	int rc;
	struct lnx_ep *my_ep;

	rc = lnx_alloc_endpoint(domain, info, &my_ep, context, FI_CLASS_EP);
	if (rc)
		return rc;

	*ep = &my_ep->le_ep.ep_fid;

	return 0;
}


