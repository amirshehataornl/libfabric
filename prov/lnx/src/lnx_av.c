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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rdma/fi_errno.h>
#include "ofi_util.h"
#include "ofi.h"
#include "ofi_str.h"
#include "ofi_prov.h"
#include "ofi_perf.h"
#include "ofi_hmem.h"
#include "rdma/fi_ext.h"
#include "lnx.h"

struct lnx_peer *
lnx_av_lookup_addr(struct lnx_av *av, fi_addr_t addr)
{
	struct lnx_peer *lp, **lpp;

	if (addr == FI_ADDR_UNSPEC)
		return NULL;

	ofi_genlock_lock(&av->lav_domain->ld_domain.lock);

	lpp = ofi_av_get_addr(&av->lav_av, addr);
	lp = *lpp;

	ofi_genlock_unlock(&av->lav_domain->ld_domain.lock);

	if (!lp)
		FI_WARN(&lnx_prov, FI_LOG_CORE,
			"Invalid fi_addr %#lx\n", addr);

	return lp;
}

int lnx_av_close(struct fid *fid)
{
	int rc, frc = 0;
	struct lnx_core_av *core_av;
	struct lnx_av *lav;

	lav = container_of(fid, struct lnx_av, lav_av.av_fid.fid);

	dlist_foreach_container(&lav->lav_core_avs, struct lnx_core_av,
				core_av, cav_entry) {
		rc = fi_close(&core_av->cav_av->fid);
		if (rc)
			frc = rc;
	}

	ofi_av_close(&lav->lav_av);
	free(lav);

	return frc;
}

static struct fi_ops lnx_av_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = lnx_av_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static void
lnx_update_msg_entries(struct lnx_qpair *qp,
		       fi_addr_t (*get_addr)(struct fi_peer_rx_entry *))
{
	struct lnx_queue *q = &qp->lqp_unexq;
	struct lnx_rx_entry *rx_entry;
	struct dlist_entry *item;

	ofi_spin_lock(&q->lq_qlock);
	dlist_foreach(&q->lq_queue, item) {
		rx_entry = (struct lnx_rx_entry *) item;
		if (rx_entry->rx_entry.addr == FI_ADDR_UNSPEC)
			rx_entry->rx_entry.addr =
			  lnx_decode_primary_id(get_addr(&rx_entry->rx_entry));
	}
	ofi_spin_unlock(&q->lq_qlock);
}

void
lnx_foreach_unspec_addr(struct fid_peer_srx *srx,
			fi_addr_t (*get_addr)(struct fi_peer_rx_entry *))
{
	struct lnx_ep *lep;
	struct lnx_core_ep *cep;

	cep = (struct lnx_core_ep *) srx->ep_fid.fid.context;
	lep = cep->cep_parent;

	lnx_update_msg_entries(&lep->le_srq.lps_trecv, get_addr);
	lnx_update_msg_entries(&lep->le_srq.lps_recv, get_addr);
}

static int lnx_peer_av_remove(struct lnx_peer *lp)
{
	int i, rc, frc = 0;
	struct lnx_peer_ep_info *pei;
	struct lnx_peer_av_info *pai;
	struct dlist_entry *tmp;
	fi_addr_t *core_addr;

	dlist_foreach_container_safe(&lp->lp_avs,
			struct lnx_peer_av_info, pai, pai_entry, tmp) {
		dlist_remove(&pai->pai_entry);
		core_addr = ofi_bufpool_get_ibuf(pai->pai_av->cav_map, lp->lp_addr);
		if (!core_addr)
			continue;
		for (i = 0; i <= pai->pai_idx; i++) {
			rc = fi_av_remove(pai->pai_av->cav_av, &core_addr[i], 1, 0);
			if (rc)
				frc = rc;
		}
	}

	/* cleanup the eps off the peer list */
	dlist_foreach_container_safe(&lp->lp_eps, struct lnx_peer_ep_info, pei,
				     pei_entry, tmp) {
		dlist_remove(&pei->pei_entry);
		free(pei);
	}

	return frc;
}

static int lnx_peer_remove(struct lnx_av *lav, fi_addr_t addr)
{
	struct lnx_peer *lp, **lpp;
	int rc = 0;

	ofi_genlock_lock(&lav->lav_domain->ld_domain.lock);
	lpp = ofi_av_get_addr(&lav->lav_av, addr);
	if (!lpp)
		goto out;

	lp = *lpp;

	rc = lnx_peer_av_remove(lp);

	rc = ofi_av_remove_addr(&lav->lav_av, addr);

	free(lp);

out:
	ofi_genlock_unlock(&lav->lav_domain->ld_domain.lock);
	return rc;
}

int lnx_av_remove(struct fid_av *av, fi_addr_t *fi_addr, size_t count,
		  uint64_t flags)
{
	struct lnx_av *lav;
	int frc = 0, rc, i;

	lav = container_of(av, struct lnx_av, lav_av.av_fid.fid);

	for (i = 0; i < count; i++) {
		rc = lnx_peer_remove(lav, fi_addr[i]);
		if (rc)
			frc = rc;
	}

	return frc;
}

static int
lnx_insert_addr(struct lnx_core_av *core_av, struct lnx_ep_addr *addr,
		struct lnx_peer *lp, bool local, char *h1, char *h2)
{
	int rc;
	char *prov_name;
	void *core_addr = (char*) addr + sizeof(*addr);
	struct lnx_peer_ep_info *pei;
	struct lnx_peer_av_info *pai;
	struct lnx_core_ep *cep;
	fi_addr_t core_fi_addr;
	fi_addr_t *map_addr;

	prov_name = core_av->cav_domain->cd_info->fabric_attr->name;
	/* only insert into AVs belonging to compatible domains */
	if (strcmp(prov_name, addr->lea_prov))
		return FI_SUCCESS;
	if (!local && !strcmp(addr->lea_prov, "shm"))
		return FI_SUCCESS;

	dlist_foreach_container(&lp->lp_avs, struct lnx_peer_av_info,
				pai, pai_entry) {
		if (pai->pai_av == core_av) {
			pai->pai_idx++;
			goto insert;
		}
	}

	pai = calloc(sizeof(*pai), 1);
	if (!pai)
		return -FI_ENOMEM;
	dlist_init(&pai->pai_entry);
	pai->pai_av = core_av;
	dlist_insert_tail(&pai->pai_entry, &lp->lp_avs);

insert:
	core_fi_addr = lnx_encode_fi_addr(lp->lp_addr, pai->pai_idx);

	rc = fi_av_insert(core_av->cav_av, core_addr, 1, &core_fi_addr, FI_AV_USER_ID, NULL);
	if (rc <= 0) {
		dlist_remove(&pai->pai_entry);
		free(pai);
		return rc;
	}

	/* map lnx fi_addr -> core fi_addr
	 * This allows us to lookup the core fi_addr using the lnx fi_addr
	 * in av
	 */
	if (pai->pai_idx == 0) {
		map_addr = ofi_ibuf_alloc_at(core_av->cav_map, lp->lp_addr);
		if (!map_addr)
			return -FI_ENOMEM;
	} else {
		map_addr = ofi_bufpool_get_ibuf(core_av->cav_map, lp->lp_addr);
	}

	map_addr[pai->pai_idx] = core_fi_addr;

	/* insert all the eps bound to the cav on the peer */
	dlist_foreach_container(&core_av->cav_ep_list, struct lnx_core_ep,
				cep, cep_av_entry) {
		pei = calloc(sizeof(*pei), 1);
		if (!pei)
			return -FI_ENOMEM;
		dlist_init(&pei->pei_entry);
		pei->pei_cep = cep;
		dlist_insert_tail(&pei->pei_entry, &lp->lp_eps);
		lp->lp_total_eps++;
	}

	return FI_SUCCESS;
}

int lnx_av_insert(struct fid_av *av, const void *addr, size_t count,
		  fi_addr_t *fi_addr, uint64_t flags, void *context)
{
	int i, j, rc;
	bool local, once;
	int disable_shm = 0;
	struct lnx_peer *lp;
	char hostname[FI_NAME_MAX];
	struct lnx_av *lav;
	struct lnx_address *la;
	struct lnx_ep_addr *lea;
	struct lnx_core_av *core_av;

	if (flags & FI_AV_USER_ID)
		return -FI_ENOSYS;

	fi_param_get_bool(&lnx_prov, "disable_shm", &disable_shm);

	lav = container_of(av, struct lnx_av, lav_av.av_fid.fid);

	rc = gethostname(hostname, FI_NAME_MAX);

	la = (struct lnx_address *) addr;
	for (i = 0; i < count; i++) {
		once = false;
		local = false;

		lea = (struct lnx_ep_addr *) ((char*)la + sizeof(*la));
		lp = calloc(sizeof(*lp), 1);
		if (!lp)
			return -FI_ENOMEM;

		dlist_init(&lp->lp_avs);
		dlist_init(&lp->lp_eps);
		if (!strcmp(hostname, la->la_hostname) && !disable_shm)
			local = true;

		ofi_genlock_lock(&lav->lav_domain->ld_domain.lock);
		rc = ofi_av_insert_addr(&lav->lav_av, &lp, &lp->lp_addr);
		if (rc) {
			ofi_genlock_unlock(&lav->lav_domain->ld_domain.lock);
			return rc;
		}
		ofi_genlock_unlock(&lav->lav_domain->ld_domain.lock);

		if (fi_addr)
			fi_addr[i] = lp->lp_addr;

		/* NOTE: the shm av table will be the first on the list.
		 * if the peer is local then we only insert the shm
		 * address and skip all the other peer addresses as we
		 * will only talk to it over shared memory
		 */
		for (j = 0; j < la->la_ep_count; j++) {
			if (once)
				goto skip;
			dlist_foreach_container(&lav->lav_core_avs, struct lnx_core_av,
						core_av, cav_entry) {
				rc = lnx_insert_addr(core_av, lea, lp, local,
						     hostname, la->la_hostname);
				if (rc) {
					(void) lnx_av_remove(&lav->lav_av.av_fid,
							     &lp->lp_addr, 1, 0);
					return rc;
				}
				if (local) {
					once = true;
					break;
				}
			}
skip:
			lea = (struct lnx_ep_addr *)
				((char*)lea + sizeof(*lea) + lea->lea_addr_size);
		}
		la = (struct lnx_address *) lea;
	}

	return i;
}

static const char *
lnx_av_straddr(struct fid_av *av, const void *addr,
	       char *buf, size_t *len)
{
	/* TODO: implement */
	return NULL;
}

static int
lnx_av_lookup(struct fid_av *av, fi_addr_t fi_addr, void *addr,
	      size_t *addrlen)
{
	/* TODO: implement */
	return -FI_EOPNOTSUPP;
}

static struct fi_ops_av lnx_av_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = lnx_av_insert,
	.remove = lnx_av_remove,
	.insertsvc = fi_no_av_insertsvc,
	.insertsym = fi_no_av_insertsym,
	.lookup = lnx_av_lookup,
	.straddr = lnx_av_straddr,
};

int lnx_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
		struct fid_av **av_out, void *context)
{
	struct fi_info *fi;
	struct lnx_domain *lnx_domain;
	struct lnx_core_domain *cd;
	struct lnx_av *av;
	struct lnx_core_av *core_av;
	struct util_av_attr util_attr = {0};
	size_t table_sz;
	int rc = 0;
	struct ofi_bufpool_attr pool_attr = {
		.size = sizeof(fi_addr_t)*LNX_MAX_LOCAL_EPS,
		.flags = OFI_BUFPOOL_NO_TRACK | OFI_BUFPOOL_INDEXED,
	};

	if (!attr)
		return -FI_EINVAL;

	if (attr->name)
		return -FI_ENOSYS;

	if (attr->type != FI_AV_TABLE)
		return -FI_ENOSYS;

	lnx_domain = container_of(domain, struct lnx_domain,
				  ld_domain.domain_fid.fid);

	av = calloc(sizeof(*av), 1);
	if (!av)
		return -FI_ENOMEM;

	dlist_init(&av->lav_core_avs);

	table_sz = attr->count ? attr->count : ofi_universe_size;
	table_sz = roundup_power_of_two(table_sz);
	pool_attr.chunk_cnt = table_sz;

	util_attr.addrlen = sizeof(struct lnx_peer *);
	rc = ofi_av_init(&lnx_domain->ld_domain, attr,
			 &util_attr, &av->lav_av, context);
	if (rc) {
		FI_WARN(&lnx_prov, FI_LOG_CORE,
			"failed to initialize AV: %d\n", rc);
		goto out;
	}

	av->lav_max_count = table_sz;
	av->lav_domain = lnx_domain;
	av->lav_av.av_fid.fid.ops = &lnx_av_fi_ops;
	av->lav_av.av_fid.ops = &lnx_av_ops;

	/* walk through the rest of the core providers and open their
	 * respective address vector tables
	 */
	dlist_foreach_container(&lnx_domain->ld_core_domains, struct lnx_core_domain,
				cd, cd_entry) {
		core_av = calloc(sizeof(*core_av), 1);
		if (!core_av)
			return -FI_ENOMEM;
		dlist_init(&core_av->cav_entry);
		dlist_init(&core_av->cav_peer_entry);
		dlist_init(&core_av->cav_ep_list);
		core_av->cav_domain = cd;
		fi = cd->cd_info;
		attr->type = FI_AV_TABLE;
		attr->count = fi->domain_attr->ep_cnt;
		rc = fi_av_open(cd->cd_domain, attr, &core_av->cav_av, context);
		if (rc) {
			free(core_av);
			goto failed;
		}

		rc = ofi_bufpool_create_attr(&pool_attr, &core_av->cav_map);
		if (rc) {
			free(core_av);
			goto failed;
		}

		dlist_insert_tail(&core_av->cav_entry, &av->lav_core_avs);
	}

	*av_out = &av->lav_av.av_fid;

	return 0;

failed:
	ofi_av_close(&av->lav_av);
	free(av);
out:
	return rc;
}


