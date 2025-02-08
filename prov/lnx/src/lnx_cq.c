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

ssize_t lnx_peer_cq_write(struct fid_peer_cq *cq, void *context, uint64_t flags,
			size_t len, void *buf, uint64_t data, uint64_t tag,
			fi_addr_t src)
{
	struct lnx_cq *lnx_cq;
	int rc;

	lnx_cq = container_of(cq, struct lnx_cq, lcq_peer_cq);

	rc = ofi_cq_write(&lnx_cq->lcq_util_cq, context,
			  flags, len, buf, data, tag);

	return rc;
}

ssize_t lnx_peer_cq_writeerr(struct fid_peer_cq *cq,
			const struct fi_cq_err_entry *err_entry)
{
	struct lnx_cq *lnx_cq;
	int rc;

	lnx_cq = container_of(cq, struct lnx_cq, lcq_peer_cq);

	rc = ofi_cq_write_error(&lnx_cq->lcq_util_cq, err_entry);

	return rc;
}

static int lnx_cq_close(struct fid *fid)
{
	int rc, frc = 0;
	struct lnx_cq *lnx_cq;
	struct dlist_entry *tmp;
	struct lnx_core_cq *core_cq;

	lnx_cq = container_of(fid, struct lnx_cq, lcq_util_cq.cq_fid.fid);

	/* Kick the core provider endpoints to progress */
	dlist_foreach_container_safe(&lnx_cq->lcq_core_cqs, struct lnx_core_cq,
				core_cq, cc_entry, tmp) {
		dlist_remove(&core_cq->cc_entry);
		rc = fi_close(&core_cq->cc_cq->fid);
		if (rc)
			frc = rc;
		free(core_cq);
	}

	rc = ofi_cq_cleanup(&lnx_cq->lcq_util_cq);
	if (rc)
		frc = rc;

	free(lnx_cq);

	return frc;
}

struct fi_ops_cq_owner lnx_cq_write = {
	.size = sizeof(lnx_cq_write),
	.write = lnx_peer_cq_write,
	.writeerr = lnx_peer_cq_writeerr,
};

static struct fi_ops lnx_cq_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = lnx_cq_close,
	.bind = fi_no_bind,
	.control = ofi_cq_control,
	.ops_open = fi_no_ops_open,
};

static void lnx_cq_progress(struct util_cq *cq)
{
	struct lnx_cq *lnx_cq;
	struct lnx_core_cq *core_cq;

	lnx_cq = container_of(cq, struct lnx_cq, lcq_util_cq);

	/* Kick the core provider endpoints to progress */
	dlist_foreach_container(&lnx_cq->lcq_core_cqs, struct lnx_core_cq,
				core_cq, cc_entry) {
		fi_cq_read(core_cq->cc_cq, NULL, 0);
	}
}

static int lnx_open_core_cqs(struct lnx_cq *lnx_cq, struct fi_cq_attr *attr)
{
	int rc;
	struct fi_cq_attr peer_attr = {0};
	struct lnx_core_domain *cd;
	struct lnx_core_cq *core_cq;
	struct fi_peer_cq_context cq_ctxt;
	struct dlist_entry *domains = &lnx_cq->lcq_lnx_domain->ld_core_domains;

	/* tell the core providers to import my CQ */
	peer_attr.flags |= FI_PEER;

	/* create all the core provider completion queues */
	dlist_foreach_container(domains, struct lnx_core_domain,
				cd, cd_entry) {
		core_cq = calloc(sizeof(*core_cq), 1);
		if (!core_cq)
			return -FI_ENOMEM;

		dlist_init(&core_cq->cc_entry);

		lnx_cq->lcq_peer_cq.owner_ops = &lnx_cq_write;

		cq_ctxt.size = sizeof(cq_ctxt);
		cq_ctxt.cq = &lnx_cq->lcq_peer_cq;

		/* pass my CQ into the open and get back the core's cq */
		rc = fi_cq_open(cd->cd_domain, &peer_attr, &core_cq->cc_cq, &cq_ctxt);
		if (rc)
			return rc;

		core_cq->cc_domain = cd;

		dlist_insert_tail(&core_cq->cc_entry, &lnx_cq->lcq_core_cqs);
	}

	return 0;
}

int lnx_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		struct fid_cq **cq_fid, void *context)
{
	struct lnx_cq *lnx_cq;
	struct lnx_domain *lnx_dom;
	int rc;

	lnx_cq = calloc(1, sizeof(*lnx_cq));
	if (!lnx_cq)
		return -FI_ENOMEM;

	dlist_init(&lnx_cq->lcq_core_cqs);

	/* this is going to be a standard CQ from the read side. From the
	 * write side, it'll use the peer_cq callbacks to write 
	 */
	rc = ofi_cq_init(&lnx_prov, domain, attr, &lnx_cq->lcq_util_cq,
			 &lnx_cq_progress, context);
	if (rc)
		goto free;

	lnx_dom = container_of(domain, struct lnx_domain,
			       ld_domain.domain_fid);

	lnx_cq->lcq_lnx_domain = lnx_dom;
	lnx_cq->lcq_util_cq.cq_fid.fid.ops = &lnx_cq_fi_ops;
	(*cq_fid) = &lnx_cq->lcq_util_cq.cq_fid;

	/* open core CQs and tell them to import my CQ */
	rc = lnx_open_core_cqs(lnx_cq, attr);

	return rc;

free:
	free(lnx_cq);
	return rc;
}
