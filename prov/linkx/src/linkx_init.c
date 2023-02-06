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
#include "linkx.h"

#define LNX_PASSTHRU_TX_OP_FLAGS	(FI_INJECT_COMPLETE | \
					 FI_TRANSMIT_COMPLETE | \
					 FI_DELIVERY_COMPLETE)
#define LNX_PASSTHRU_RX_OP_FLAGS	(0ULL)
#define LNX_TX_OP_FLAGS		(FI_INJECT_COMPLETE | FI_COMPLETION | \
							 FI_DELIVERY_COMPLETE | FI_TRANSMIT_COMPLETE)
#define LNX_RX_OP_FLAGS		(FI_COMPLETION)

struct local_prov *shm_prov;
struct util_fabric lnx_fabric_info;

DEFINE_LIST(local_prov_table);

struct fi_tx_attr lnx_tx_attr = {
	.caps 		= ~0x0ULL,
	.op_flags	= LNX_PASSTHRU_TX_OP_FLAGS | LNX_TX_OP_FLAGS,
	.msg_order 	= ~0x0ULL,
	.comp_order 	= ~0x0ULL,
	.inject_size 	= SIZE_MAX,
	.size 		= SIZE_MAX,
	.iov_limit 	= LNX_IOV_LIMIT,
	.rma_iov_limit = LNX_IOV_LIMIT,
};

struct fi_rx_attr lnx_rx_attr = {
	.caps 			= ~0x0ULL,
	.op_flags		= LNX_PASSTHRU_RX_OP_FLAGS | LNX_RX_OP_FLAGS,
	.msg_order 		= ~0x0ULL,
	.comp_order 		= ~0x0ULL,
	.total_buffered_recv 	= SIZE_MAX,
	.size 			= 1024,
	.iov_limit		= LNX_IOV_LIMIT,
};

struct fi_ep_attr lnx_ep_attr = {
	.type 			= FI_EP_UNSPEC,
	.protocol 		= FI_PROTO_LINKX,
	.protocol_version 	= 1,
	.max_msg_size 		= SIZE_MAX,
	.msg_prefix_size	= SIZE_MAX,
	.max_order_raw_size 	= SIZE_MAX,
	.max_order_war_size 	= SIZE_MAX,
	.max_order_waw_size 	= SIZE_MAX,
	.mem_tag_format = FI_TAG_GENERIC,
	.tx_ctx_cnt 		= SIZE_MAX,
	.rx_ctx_cnt 		= SIZE_MAX,
	.auth_key_size		= SIZE_MAX,
};

struct fi_domain_attr lnx_domain_attr = {
	.name			= "ofi_lnx_domain",
	.threading 		= FI_THREAD_SAFE,
	.control_progress 	= FI_PROGRESS_AUTO,
	.data_progress 		= FI_PROGRESS_AUTO,
	.resource_mgmt 		= FI_RM_ENABLED,
	.av_type 		= FI_AV_UNSPEC,
	.mr_mode 		= FI_MR_BASIC | FI_MR_SCALABLE | FI_MR_RAW,
	.mr_key_size		= SIZE_MAX,
	.cq_data_size 		= SIZE_MAX,
	.cq_cnt 		= SIZE_MAX,
	.ep_cnt 		= SIZE_MAX,
	.tx_ctx_cnt 		= SIZE_MAX,
	.rx_ctx_cnt 		= SIZE_MAX,
	.max_ep_tx_ctx 		= SIZE_MAX,
	.max_ep_rx_ctx 		= SIZE_MAX,
	.max_ep_stx_ctx 	= SIZE_MAX,
	.max_ep_srx_ctx 	= SIZE_MAX,
	.cntr_cnt 		= SIZE_MAX,
	.mr_iov_limit 		= SIZE_MAX,
	.caps			= ~0x0ULL,
	.auth_key_size		= SIZE_MAX,
	.max_err_data		= SIZE_MAX,
	.mr_cnt			= SIZE_MAX,
};

struct fi_fabric_attr lnx_fabric_attr = {
	.prov_version = OFI_VERSION_DEF_PROV,
	.name = "ofi_lnx_fabric",
};

struct fi_info lnx_info = {
	.caps = ~0x0ULL,
	.tx_attr = &lnx_tx_attr,
	.rx_attr = &lnx_rx_attr,
	.ep_attr = &lnx_ep_attr,
	.domain_attr = &lnx_domain_attr,
	.fabric_attr = &lnx_fabric_attr
};

static struct fi_ops lnx_fabric_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = lnx_fabric_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_fabric lnx_fabric_ops = {
	.size = sizeof(struct fi_ops_fabric),
	.domain = lnx_domain_open,
	.passive_ep = fi_no_passive_ep,
	.eq_open = fi_no_eq_open,
	.wait_open = fi_no_wait_open,
	.trywait = fi_no_trywait
};

struct fi_provider lnx_prov = {
	.name = OFI_LINKX,
	.version = OFI_VERSION_DEF_PROV,
	.fi_version = OFI_VERSION_LATEST,
	.getinfo = lnx_getinfo,
	.fabric = lnx_fabric,
	.cleanup = lnx_fini
};

struct util_prov lnx_util_prov = {
	.prov = &lnx_prov,
	.info = &lnx_info,
	.flags = 0
};

struct lnx_fi_info_cache {
	struct fi_info *cache_info;
};

/*
 * For the fi_getinfo() -> fi_fabric() -> fi_domain() path, we need to
 * keep track of the fi_info in case we need them later on when linking in
 * the fi_fabric() function.
 *
 * This cache gets cleared after we use the ones we need, or when the
 * library exists, if LINKx is never used.
 */
static struct lnx_fi_info_cache lnx_fi_info_cache[LNX_MAX_LOCAL_EPS] = {0};

static void lnx_free_info_cache(void)
{
	int i;

	/* free the cache if there are any left */
	for (i = 0; i < LNX_MAX_LOCAL_EPS; i++) {
		if (lnx_fi_info_cache[i].cache_info) {
			fi_freeinfo(lnx_fi_info_cache[i].cache_info);
			lnx_fi_info_cache[i].cache_info = NULL;
		}
	}
}

static int lnx_cache_info(struct fi_info *info, int idx)
{
	struct fi_info *prov_info;

	/* exceeded the number of supported providers */
	if (idx >= LNX_MAX_LOCAL_EPS)
		return -FI_ENODATA;

	/* stash this fi info */
	lnx_fi_info_cache[idx].cache_info = fi_dupinfo(info);
	prov_info = lnx_fi_info_cache[idx].cache_info;
	if (!lnx_fi_info_cache[idx].cache_info)
		return -FI_ENODATA;

	FI_INFO(&lnx_prov, FI_LOG_CORE, "Caching %s\n",
			prov_info->fabric_attr->prov_name);
	prov_info->next = NULL;

	return 0;
}

static struct fi_info *
lnx_get_cache_entry_by_prov(char *prov_name, bool remove)
{
	int i;

	/* free the cache if there are any left */
	for (i = 0; i < LNX_MAX_LOCAL_EPS; i++) {
		struct fi_info *info = lnx_fi_info_cache[i].cache_info;

		if (info && info->fabric_attr) {
			if (!strcmp(prov_name,
						info->fabric_attr->prov_name)) {
				/* this will be freed lnx_cleanup_eps() */
				if (remove)
					lnx_fi_info_cache[i].cache_info = NULL;
				FI_INFO(&lnx_prov, FI_LOG_CORE, "Found %s\n",
						info->fabric_attr->prov_name);
				return info;
			}
		}
	}

	return NULL;
}

struct fi_info *
lnx_get_cache_entry_by_dom(char *domain_name)
{
	int i;

	/* free the cache if there are any left */
	for (i = 0; i < LNX_MAX_LOCAL_EPS; i++) {
		struct fi_info *info = lnx_fi_info_cache[i].cache_info;

		if (info && info->domain_attr) {
			if (!strcmp(domain_name,
						info->domain_attr->name)) {
				/* this will be freed lnx_cleanup_eps() */
				lnx_fi_info_cache[i].cache_info = NULL;
				FI_INFO(&lnx_prov, FI_LOG_CORE, "Found %s\n",
						info->domain_attr->name);
				return info;
			}
		}
	}

	return NULL;
}

static int lnx_generate_info(struct fi_info *ci, struct fi_info **info,
							 int idx)
{
	struct fi_info *itr, *fi, *tail, *shm;
	char *s, *prov_name, *domain;
	int rc, num = idx, num_shm = idx, i;

	shm = lnx_get_cache_entry_by_prov("shm", false);
	if (!shm)
		return -FI_ENODATA;

	*info = tail = NULL;
	for (itr = ci; itr; itr = itr->next) {
		if (itr->fabric_attr->prov_name &&
			!strcmp(itr->fabric_attr->prov_name, "shm"))
			continue;

		rc = lnx_cache_info(itr, num);
		if (rc)
			goto err;

		for (i = 0; i < num_shm; i++) {
			fi = fi_dupinfo(itr);
			if (!fi)
				return -FI_ENOMEM;

			/* We only link providers with matching endpoint
			 * types */
			if (ofi_check_ep_type(&lnx_prov, fi->ep_attr,
					      shm->ep_attr)) {
				fi_freeinfo(fi);
				goto err;
			}

			free(fi->fabric_attr->name);
			domain = fi->domain_attr->name;
			prov_name = fi->fabric_attr->prov_name;

			fi->fabric_attr->name = NULL;
			fi->domain_attr->name = NULL;
			fi->fabric_attr->prov_name = NULL;

			if (asprintf(&s, "shm+%s", prov_name) < 0) {
				free(prov_name);
				fi_freeinfo(fi);
				goto err;
			}
			free(prov_name);
			fi->fabric_attr->prov_name = s;

			if (asprintf(&s, "%s", lnx_info.fabric_attr->name) < 0) {
				fi_freeinfo(fi);
				goto err;
			}
			fi->fabric_attr->name = s;

			if (asprintf(&s, "shm+%s:%s", domain, lnx_info.domain_attr->name) < 0) {
				free(domain);
				fi_freeinfo(fi);
				goto err;
			}
			free(domain);
			fi->domain_attr->name = s;

			/* TODO: ofi_endpoint_init() looks at the ep_attr in detail to
			* make sure it matches between what's passed in by the user and
			* what's given by the provider. That's why we just copy the
			* provider ep_attr into what we return to the user.
			*/
			memcpy(fi->ep_attr, lnx_info.ep_attr, sizeof(*lnx_info.ep_attr));
			fi->fabric_attr->prov_version = lnx_info.fabric_attr->prov_version;
			fi->ep_attr->type = shm->ep_attr->type;

			if (!tail)
				*info = fi;
			else
				tail->next = fi;
			tail = fi;
		}

		num++;
	}

	if (num == idx)
		return -FI_ENODATA;

	return 0;

err:
	fi_freeinfo(*info);
	lnx_free_info_cache();

	return -FI_ENODATA;
}

int lnx_getinfo(uint32_t version, const char *node, const char *service,
	     uint64_t flags, const struct fi_info *hints,
	     struct fi_info **info)
{
	int rc, num;
	char *orig_prov_name = NULL;
	struct fi_info *core_info, *lnx_hints, *itr;
	uint64_t caps, mr_mode;

	/* If the hints are not provided then we endup with a new block */
	lnx_hints = fi_dupinfo(hints);
	if (!lnx_hints)
		return -FI_ENOMEM;

	/* get the providers which support peer functionality. These are
	 * the only ones we can link*/
	lnx_hints->caps |= FI_PEER;
	/* we need to lookup the shm as well, so turn off FI_REMOTE_COMM
	 * and FI_LOCAL_COMM if they are set.
	 */
	caps = lnx_hints->caps;
	mr_mode = lnx_hints->domain_attr->mr_mode;

	lnx_hints->caps &= ~(FI_REMOTE_COMM | FI_LOCAL_COMM);

	FI_INFO(&lnx_prov, FI_LOG_FABRIC, "LINKX START -------------------\n");

	if (lnx_hints->fabric_attr->prov_name) {
		/* find the shm memory provider. There could be more than one. We need
		* to look it up ahead so we can generate all possible combination
		* between shm and other providers which it can link against.
		*/
		orig_prov_name = lnx_hints->fabric_attr->prov_name;
		lnx_hints->fabric_attr->prov_name = NULL;
	}

	lnx_hints->fabric_attr->prov_name = strdup("shm");
	/* make sure we get the shm provider which supports HMEM */
	lnx_hints->caps |= FI_HMEM;
	lnx_hints->domain_attr->mr_mode |= (FI_MR_VIRT_ADDR | FI_MR_HMEM
										| FI_MR_PROV_KEY);
	rc = fi_getinfo(version, NULL, NULL, OFI_GETINFO_INTERNAL,
					lnx_hints, &core_info);
	if (rc) {
		lnx_hints->fabric_attr->prov_name = orig_prov_name;
		goto free_hints;
	}

	num = 0;
	for (itr = core_info; itr; itr = itr->next) {
		rc = lnx_cache_info(itr, num);
		num++;
	}
	free(lnx_hints->fabric_attr->prov_name);

	if (!num) {
		FI_WARN(&lnx_prov, FI_LOG_FABRIC, "No SHM provider available");
		rc = -FI_ENODATA;
		goto free_hints;
	}

	lnx_hints->fabric_attr->prov_name = orig_prov_name;

	rc = ofi_exclude_prov_name(&lnx_hints->fabric_attr->prov_name,
			lnx_prov.name);
	if (rc)
		goto free_hints;

	lnx_hints->caps = caps;
	lnx_hints->domain_attr->mr_mode = mr_mode;
	rc = fi_getinfo(version, NULL, NULL,
				OFI_GETINFO_INTERNAL, lnx_hints,
				&core_info);
	if (rc)
		goto free_hints;

	FI_INFO(&lnx_prov, FI_LOG_FABRIC, "LINKX END -------------------\n");

	/* The list pointed to by core_info can all be coupled with shm. Note
	 * that shm will be included in that list, so we need to exclude it
	 * from the list
	 */
	rc = lnx_generate_info(core_info, info, num);

	fi_freeinfo(core_info);

free_hints:
	fi_freeinfo(lnx_hints);
	return rc;
}

int lnx_parse_prov_name(char *name, char *shm, char *prov)
{
	char *sub1, *sub2, *delim;
	int sub1_len, sub2_len;

	sub1 = name;

	/* the name comes in as: shm+<prov>:ofi_linkx */
	delim = strchr(sub1, '+');
	if (!delim)
		return -FI_ENODATA;

	sub1_len = delim - sub1;

	sub2 = delim + 1;
	delim = strchr(sub2, ':');
	if (!delim)
		return -FI_ENODATA;

	sub2_len = delim - sub2;

	if (shm) {
		strncpy(shm, sub1, sub1_len);
		shm[sub1_len] = '\0';
	}

	if (prov) {
		strncpy(prov, sub2, sub2_len);
		prov[sub2_len] = '\0';
	}

	return 0;
}

static struct local_prov *
lnx_get_local_prov(char *prov_name)
{
	struct local_prov *entry;

	/* close all the open core fabrics */
	dlist_foreach_container(&local_prov_table, struct local_prov,
							entry, lpv_entry) {
		if (!strncasecmp(entry->lpv_prov_name, prov_name, FI_NAME_MAX))
			return entry;
	}

	return NULL;
}

static int
lnx_add_ep_to_prov(struct local_prov *prov,
				   struct local_prov_ep *ep)
{
	int i;

	for (i = 0; i < LNX_MAX_LOCAL_EPS; i++) {
		if (prov->lpv_prov_eps[i])
			continue;
		prov->lpv_prov_eps[i] = ep;
		ep->lpe_parent = prov;
		prov->lpv_ep_count++;
		return 0;
	}

	return -FI_ENOENT;
}

static int
lnx_setup_core_prov(struct fi_info *info, void *context)
{
	int rc;
	struct local_prov_ep *entry = NULL;
	struct local_prov *lprov, *new_lprov = NULL;

	entry = calloc(sizeof(*entry), 1);
	if (!entry)
		return -FI_ENOMEM;

	new_lprov = calloc(sizeof(*new_lprov), 1);
	if (!new_lprov)
		goto free_entry;

	rc = fi_fabric(info->fabric_attr, &entry->lpe_fabric, context);
	if (rc)
		return rc;

	entry->lpe_fi_info = info;
	strncpy(entry->lpe_fabric_name, info->fabric_attr->name,
			FI_NAME_MAX - 1);

	lprov = lnx_get_local_prov(info->fabric_attr->prov_name);
	if (!lprov) {
		lprov = new_lprov;
		new_lprov = NULL;
		strncpy(lprov->lpv_prov_name, info->fabric_attr->prov_name,
				FI_NAME_MAX - 1);
	} else {
		free(new_lprov);
	}

	/* indicate that this fabric can be used for on-node communication */
	if (!strncasecmp(lprov->lpv_prov_name, "shm", 3)) {
		shm_prov = lprov;
		entry->lpe_local = true;
	}

	rc = lnx_add_ep_to_prov(lprov, entry);
	if (rc)
		goto free_all;

	dlist_insert_after(&lprov->lpv_entry, &local_prov_table);

	return 0;

free_all:
	if (new_lprov)
		free(new_lprov);
free_entry:
	if (entry)
		free(entry);

	return rc;
}

int lnx_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
		void *context)
{
	struct fi_info *info = NULL;
	char shm[FI_NAME_MAX];
	char prov[FI_NAME_MAX];
	int rc;
	/*
	 * provider: shm+cxi:linkx
	 *     fabric: ofi_lnx_fabric
	 *     domain: shm+cxi3:ofi_lnx_domain
	 *     version: 120.0
	 *     type: FI_EP_RDM
	 *     protocol: FI_PROTO_LINKX
	 *
	 * Parse out the provider name. It should be shm+<prov>
	 *
	 * Create a fabric for shm and one for the other provider.
	 *
	 * When fi_domain() is called, we get the fi_info for the
	 * second provider, which we should've returned as part of the
	 * fi_getinfo() call.
	 */
	/* create a new entry for shm.
	 * Create its fabric.
	 * insert fabric in the global table
	 */
	rc = lnx_parse_prov_name(attr->prov_name, shm, prov);
	if (rc)
		goto fail;

	info = lnx_get_cache_entry_by_prov(shm, true);
	if (!info) {
		rc = -FI_ENODATA;
		goto fail;
	}

	rc = lnx_setup_core_prov(info, context);
	if (rc)
		goto fail;

	info = lnx_get_cache_entry_by_prov(prov, true);
	if (!info) {
		rc = -FI_ENODATA;
		goto fail;
	}

	rc = lnx_setup_core_prov(info, context);
	if (rc)
		goto fail;

	memset(&lnx_fabric_info, 0, sizeof(lnx_fabric_info));

	rc = ofi_fabric_init(&lnx_prov, lnx_info.fabric_attr,
						 lnx_info.fabric_attr, &lnx_fabric_info, context);
	if (rc)
		goto fail;

	lnx_fabric_info.fabric_fid.fid.ops = &lnx_fabric_fi_ops;
	lnx_fabric_info.fabric_fid.ops = &lnx_fabric_ops;
	*fabric = &lnx_fabric_info.fabric_fid;

	return 0;

fail:
	fi_freeinfo(info);
	return rc;
}

void lnx_fini(void)
{
	lnx_free_info_cache();
}

static int lnx_free_ep(struct local_prov *prov, int idx)
{
	int rc;
	struct local_prov_ep *ep;

	if (!prov || !prov->lpv_prov_eps[idx])
		return FI_SUCCESS;

	ep = prov->lpv_prov_eps[idx];
	rc = fi_close(&ep->lpe_fabric->fid);
	fi_freeinfo(ep->lpe_fi_info);
	free(ep);
	prov->lpv_prov_eps[idx] = NULL;
	prov->lpv_ep_count--;

	if (prov->lpv_ep_count == 0)
		dlist_remove(&prov->lpv_entry);

	return rc;
}

static int lnx_cleanup_eps(struct local_prov *prov)
{
	int i;
	int rc, frc = 0;

	for (i = 0; i < LNX_MAX_LOCAL_EPS; i++) {
		rc = lnx_free_ep(prov, i)
		if (rc)
			frc = rc;
	}

	return frc;
}

int ofi_create_link(struct fi_info *prov_list,
					struct fid_fabric **fabric,
					uint64_t caps, void *context)
{
	int rc;
	struct fi_info *prov;

	/* create the fabric for the list of providers 
	 * TODO: modify the code to work with the new data structures */
	for (prov = prov_list; prov; prov = prov->next) {
		struct fi_info *info = fi_dupinfo(prov);

		if (!info)
			return -FI_ENODATA;

		rc = lnx_setup_core_prov(prov, context);
		if (rc)
			return rc;
	}

	memset(&lnx_fabric_info, 0, sizeof(lnx_fabric_info));

	rc = ofi_fabric_init(&lnx_prov, lnx_info.fabric_attr,
						 lnx_info.fabric_attr, &lnx_fabric_info, context);
	if (rc)
		return rc;

	lnx_fabric_info.fabric_fid.fid.ops = &lnx_fabric_fi_ops;
	lnx_fabric_info.fabric_fid.ops = &lnx_fabric_ops;
	*fabric = &lnx_fabric_info.fabric_fid;

	return 0;
}

int lnx_fabric_close(struct fid *fid)
{
	int rc = 0;
	struct util_fabric *fabric;
	struct local_prov *entry;
	struct dlist_entry *tmp;

	/* close all the open core fabrics */
	dlist_foreach_container_safe(&local_prov_table, struct local_prov,
								 entry, lpv_entry, tmp) {
		dlist_remove(&entry->lpv_entry);
		rc = lnx_cleanup_eps(entry);
		if (rc)
			FI_WARN(&lnx_prov, FI_LOG_CORE, "Failed to close provider %s\n",
					entry->lpv_prov_name);

		free(entry);
	}

	fabric = container_of(fid, struct util_fabric, fabric_fid.fid);
	rc = ofi_fabric_close(fabric);

	return rc;
}

void ofi_link_fini(void)
{
	lnx_prov.cleanup();
}

#define LNX_MAX_RR_ENTRIES 1024 * 2
ofi_spin_t global_fslock;
struct lnx_recv_fs *global_recv_fs;

LNX_INI
{
	fi_param_define(&lnx_prov, "srq_support", FI_PARAM_BOOL,
			"Turns shared receive queue support on and off. By default it is on. "
			"When SRQ is turned on some Hardware offload capability will not "
			"work. EX: Hardware Tag matching");

	global_recv_fs = lnx_recv_fs_create(LNX_MAX_RR_ENTRIES, NULL, NULL);
	ofi_spin_init(&global_fslock);

	return &lnx_prov;
}
