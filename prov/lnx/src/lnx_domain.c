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

static struct fi_ops_domain lnx_domain_ops = {
	.size = sizeof(struct fi_ops_domain),
	.av_open = lnx_av_open,
	.cq_open = lnx_cq_open,
	.endpoint = lnx_endpoint,
	.scalable_ep = lnx_scalable_ep,
	.cntr_open = fi_no_cntr_open,
	.poll_open = fi_no_poll_open,
	.stx_ctx = fi_no_stx_context,
	.srx_ctx = fi_no_srx_context,
	.query_atomic = fi_no_query_atomic,
	.query_collective = fi_no_query_collective,
};

static int lnx_domain_close(struct fid *fid)
{
	int rc, frc = 0;
	struct lnx_domain *domain;
	struct lnx_core_domain *cd;
	struct dlist_entry *tmp;

	domain = container_of(fid, struct lnx_domain, ld_domain.domain_fid.fid);

	/* close all the open core domains */
	dlist_foreach_container_safe(&domain->ld_core_domains, struct lnx_core_domain,
				     cd, cd_entry, tmp) {
		dlist_remove(&cd->cd_entry);
		rc = fi_close(&cd->cd_domain->fid);
		if (rc)
			frc = rc;
	}

	rc = ofi_domain_close(&domain->ld_domain);
	if (rc)
		frc = rc;

	free(domain);

	return frc;
}

static struct fi_ops lnx_domain_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = lnx_domain_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_mr lnx_mr_ops = {
	.size = sizeof(struct fi_ops_mr),
	.reg = fi_no_mr_reg,
	.regv = fi_no_mr_regv,
	.regattr = lnx_mr_regattr,
};

static int lnx_open_core_domains(struct dlist_entry *core_fabrics,
				void *context, struct lnx_domain *lnx_domain,
				struct fi_info *info)
{
	int rc;
	char *prov_name;
	bool local;
	struct fi_info *itr;
	struct lnx_core_fabric *cf;
	struct lnx_core_domain *cd;

	dlist_foreach_container(core_fabrics, struct lnx_core_fabric,
				cf, cf_entry) {
		/* special case for CXI provider. We need to turn off tag
		 * matching HW offload if we're going to support shared
		 * receive queues.
		 */
		local = false;
		prov_name = cf->cf_info->fabric_attr->name;
		if (strstr(prov_name, "cxi"))
			setenv("FI_CXI_RX_MATCH_MODE", "software", 1);
		else if (!strcmp(prov_name, "shm"))
			local = true;

		for (itr = cf->cf_info; itr; itr = itr->next) {
			cd = calloc(sizeof(*cd), 1);
			if (!cd)
				return -FI_ENOMEM;

			cd->cd_info = itr;
			dlist_init(&cd->cd_entry);
			dlist_init(&cd->cd_endpoints);

			rc = fi_domain(cf->cf_fabric, cf->cf_info,
				&cd->cd_domain, context);

			/* keep the shm domain at the head of the list.
			 * This will cause all the other shm constructs to
			 * be the head of their respective lists, ex: av.
			 * The purpose is to optimize the shm path for
			 * local peers.
			 */
			if (!rc) {
				cd->cd_fabric = cf;
				if (local)
					dlist_insert_head(&cd->cd_entry,
						&lnx_domain->ld_core_domains);
				else
					dlist_insert_tail(&cd->cd_entry,
						&lnx_domain->ld_core_domains);
			} else {
				(void) lnx_domain_close(&lnx_domain->ld_domain.domain_fid.fid);
				return rc;
			}
		}
	}

	return 0;
}

/*
 * provider: shm+cxi:lnx
 *     fabric: ofi_lnx_fabric
 *     domain: shm+cxi3:ofi_lnx_domain
 *     version: 120.0
 *     type: FI_EP_RDM
 *     protocol: FI_PROTO_LNX
 *
 * Parse out the provider name. It should be shm+<prov>
 *
 * Create a fabric for shm and one for the other provider.
 *
 * When fi_domain() is called, we get the fi_info for the
 * second provider, which we should've returned as part of the
 * fi_getinfo() call.
 */
int lnx_domain_open(struct fid_fabric *fabric, struct fi_info *info,
		struct fid_domain **domain, void *context)
{
	int rc = 0;
	struct lnx_domain *lnx_domain;
	struct util_domain *dom;
	struct lnx_fabric *lnx_fab = container_of(fabric, struct lnx_fabric,
					lf_util_fabric.fabric_fid);

	rc = -FI_ENOMEM;
	lnx_domain = calloc(sizeof(*lnx_domain), 1);
	if (!lnx_domain)
		goto out;

	rc = lnx_setup_fabrics(info->domain_attr->name, lnx_fab, context);
	if (rc)
		goto fail;

	dom = &lnx_domain->ld_domain;
	lnx_domain->ld_fabric = lnx_fab;
	dlist_init(&lnx_domain->ld_core_domains);

	rc = ofi_domain_init(fabric, info, dom, context,
			     OFI_LOCK_SPINLOCK);
	if (rc)
		goto fail;

	rc = lnx_open_core_domains(&lnx_fab->lf_core_fabrics, context, lnx_domain, info);
	if (rc) {
		FI_INFO(&lnx_prov, FI_LOG_CORE, "Failed to initialize domain for %s\n",
			info->domain_attr->name);
		goto close_domain;
	}

	dom->domain_fid.fid.ops = &lnx_domain_fi_ops;
	dom->domain_fid.ops = &lnx_domain_ops;
	dom->domain_fid.mr = &lnx_mr_ops;

	*domain = &dom->domain_fid;

	return 0;

close_domain:
	lnx_domain_close(&(dom->domain_fid.fid));
fail:
	free(lnx_domain);
out:
	return rc;
}

