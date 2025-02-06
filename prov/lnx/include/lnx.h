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

#ifndef LNX_H
#define LNX_H

#define LNX_MAX_LOCAL_EPS 	16
#define LNX_IOV_LIMIT 		4
#define LNX_MAX_PRIMARY_ID	((1ULL << 56) - 1)
#define LNX_MAX_SUB_ID 		((1ULL << 8) - 1)

#define lnx_ep_rx_flags(lnx_ep) ((lnx_ep)->le_ep.rx_op_flags)

struct lnx_match_attr {
	fi_addr_t lm_addr;
	uint64_t lm_tag;
	uint64_t lm_ignore;
};

struct lnx_queue {
	struct dlist_entry lq_queue;
	dlist_func_t *lq_match_func;
	ofi_spin_t lq_qlock;
};

struct lnx_qpair {
	struct lnx_queue lqp_recvq;
	struct lnx_queue lqp_unexq;
};

struct lnx_peer_srq {
	struct lnx_qpair lps_trecv;
	struct lnx_qpair lps_recv;
};

struct lnx_core_fabric {
	struct dlist_entry cf_entry;
	char cf_prov_name[FI_NAME_MAX];
	struct fi_info *cf_info;
	struct fid_fabric *cf_fabric;
	struct dlist_entry cf_domains;
	struct local_prov *cf_prov_parent;
};

struct lnx_core_domain {
	struct dlist_entry cd_entry;
	struct fid_domain *cd_domain;
	struct lnx_core_fabric *cd_fabric;
	struct fi_info *cd_info;
	struct dlist_entry cd_endpoints;
};

struct lnx_core_av {
	/* on the lnx_av list */
	struct dlist_entry cav_entry;
	/* on the lnx_peer list */
	struct dlist_entry cav_peer_entry;
	struct fid_av *cav_av;
	struct lnx_core_domain *cav_domain;
	struct ofi_bufpool *cav_map;
	struct dlist_entry cav_ep_list;
};

struct lnx_core_ep {
	/* on the lnx_ep list */
	struct dlist_entry cep_entry;
	/* on the lnx_core_av list */
	struct dlist_entry cep_av_entry;
	struct fid_peer_srx cep_srx;
	struct fid_ep *cep_ep;
	struct fid_ep *cep_srx_ep;
	struct fid_ep **cep_txc;
	struct fid_ep **cep_rxc;
	struct lnx_core_domain *cep_domain;
	struct lnx_core_av *cep_cav;
	struct lnx_ep *cep_parent;
};

struct lnx_core_cq {
	struct dlist_entry cc_entry;
	struct fid_cq *cc_cq;
	struct lnx_core_domain *cc_domain;
};

struct lnx_peer_av_info {
	struct dlist_entry pai_entry;
	struct lnx_core_av *pai_av;
	int pai_idx;
};

struct lnx_peer_ep_info {
	struct dlist_entry pei_entry;
	struct lnx_core_ep *pei_cep;
};

struct lnx_peer {
	fi_addr_t lp_addr;
	int lp_total_eps;
	int lp_ep_rr;
	int lp_peer_rr;
	struct dlist_entry lp_avs;
	struct dlist_entry lp_eps;
};

struct lnx_av {
	struct util_av lav_av;
	int lav_max_count;
	struct lnx_domain *lav_domain;
	struct dlist_entry lav_core_avs;
};

struct lnx_mem_desc_prov {
	struct local_prov *prov;
	struct fid_mr *core_mr;
};

struct lnx_mem_desc {
	struct lnx_mem_desc_prov desc[LNX_MAX_LOCAL_EPS];
	int desc_count;
};

struct lnx_mr {
	struct ofi_mr mr;
	struct lnx_mem_desc desc;
};

struct lnx_domain {
	struct util_domain ld_domain;
	struct lnx_fabric *ld_fabric;
	struct dlist_entry ld_core_domains;
};

struct lnx_ep {
	struct util_ep le_ep;
	bool le_local;
	struct dlist_entry le_core_eps;
	struct ofi_bufpool *le_recv_bp;
	ofi_spin_t le_bplock;
	struct lnx_domain *le_domain;
	size_t le_fclass;
	struct lnx_peer_srq le_srq;
	struct lnx_av *le_lav;
	struct lnx_cq *le_lcq;
};

struct lnx_cq {
	struct util_cq lcq_util_cq;
	struct fid_peer_cq lcq_peer_cq;
	struct dlist_entry lcq_core_cqs;
	struct lnx_domain *lcq_lnx_domain;
};

struct lnx_fabric {
	struct util_fabric lf_util_fabric;
	/* providers linked by this fabric */
	struct dlist_entry lf_core_fabrics;
	/* memory registration buffer pool */
	struct ofi_bufpool *lf_mem_reg_bp;
	/* peers associated with this link */
	/* fi_info used to create this fabric */
	struct fi_info *lf_fab_fi_info;

	bool lf_fab_setup_complete;
};

struct lnx_ep_addr {
	char lea_prov[FI_NAME_MAX];
	size_t lea_addr_size;
	char lea_addr[];
};

struct lnx_address {
	char la_hostname[FI_NAME_MAX];
	int la_ep_count;
	struct lnx_ep_addr la_addrs[];
};

struct lnx_rx_entry {
	struct fi_peer_rx_entry rx_entry;
	struct iovec rx_iov[LNX_IOV_LIMIT];
	void *rx_desc[LNX_IOV_LIMIT];
	struct lnx_ep *rx_lep;
	struct lnx_core_ep *rx_cep;
	uint64_t rx_ignore;
	bool rx_global;
};

OFI_DECLARE_FREESTACK(struct lnx_rx_entry, lnx_recv_fs);


extern struct util_prov lnx_util_prov;
extern struct fi_provider lnx_prov;
extern struct ofi_bufpool *global_recv_bp;
extern ofi_spin_t global_bplock;

int lnx_getinfo(uint32_t version, const char *node, const char *service,
				uint64_t flags, const struct fi_info *hints,
				struct fi_info **info);

int lnx_fabric(struct fi_fabric_attr *attr, struct fid_fabric **fabric,
		void *context);
int lnx_setup_fabrics(char *name, struct lnx_fabric *lnx_fab, void *context);

void lnx_fini(void);

int lnx_fabric_close(struct fid *fid);

int lnx_domain_open(struct fid_fabric *fabric, struct fi_info *info,
		    struct fid_domain **dom, void *context);

int lnx_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
		struct fid_av **av, void *context);

struct lnx_peer *
lnx_av_lookup_addr(struct lnx_av *av, fi_addr_t addr);

int lnx_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		struct fid_cq **cq, void *context);

int lnx_endpoint(struct fid_domain *domain, struct fi_info *info,
		 struct fid_ep **ep, void *context);

int lnx_scalable_ep(struct fid_domain *domain, struct fi_info *info,
		    struct fid_ep **ep, void *context);

int lnx_cq2ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags);

int lnx_get_msg(struct fid_peer_srx *srx, struct fi_peer_match_attr *match,
		struct fi_peer_rx_entry **entry);
int lnx_get_tag(struct fid_peer_srx *srx, struct fi_peer_match_attr *match,
		struct fi_peer_rx_entry **entry);
int lnx_queue_msg(struct fi_peer_rx_entry *entry);
int lnx_queue_tag(struct fi_peer_rx_entry *entry);
void lnx_free_entry(struct fi_peer_rx_entry *entry);
void lnx_foreach_unspec_addr(struct fid_peer_srx *srx,
	fi_addr_t (*get_addr)(struct fi_peer_rx_entry *));

int lnx_mr_regattr(struct fid *fid, const struct fi_mr_attr *attr,
		   uint64_t flags, struct fid_mr **mr_fid);

static inline fi_addr_t
lnx_encode_fi_addr(uint64_t primary_id, uint8_t sub_id)
{
	if (primary_id > LNX_MAX_PRIMARY_ID || sub_id > LNX_MAX_SUB_ID) {
		FI_WARN(&lnx_prov, FI_LOG_CORE,
			"Error: Primary ID or Sub ID out of range.\n");
		return 0; // Return 0 to indicate error
	}
	return (primary_id << 8) | sub_id;
}

static inline fi_addr_t lnx_decode_primary_id(uint64_t fi_addr)
{
	return (fi_addr == FI_ADDR_UNSPEC) ? fi_addr : fi_addr >> 8;
}

static inline uint8_t lnx_decode_sub_id(uint64_t fi_addr)
{
	return (fi_addr == FI_ADDR_UNSPEC) ? fi_addr : fi_addr & LNX_MAX_SUB_ID;
}

static inline
void lnx_get_core_desc(struct lnx_mem_desc *desc, void **mem_desc)
{
	if (desc && desc->desc[0].core_mr) {
		if (mem_desc)
			*mem_desc = desc->desc[0].core_mr->mem_desc;
		return;
	}

	*mem_desc = NULL;
}

static inline int
lnx_select_send_endpoints(struct lnx_ep *lep, fi_addr_t lnx_addr,
		struct lnx_core_ep **cep_out, fi_addr_t *core_addr)
{
	bool pai_found = false;
	int i = 0, idx;
	struct lnx_peer *lp;
	struct lnx_peer_ep_info *pei;
	struct lnx_peer_av_info *pai;
	fi_addr_t *core_av_addrs;

	lp = lnx_av_lookup_addr(lep->le_lav, lnx_addr);
	if (!lp)
		return -FI_ENOSYS;

	/* round robin over local eps */
	lp->lp_ep_rr++;
	idx = lp->lp_ep_rr % lp->lp_total_eps;

	dlist_foreach_container(&lp->lp_eps, struct lnx_peer_ep_info,
				pei, pei_entry) {
		if (i == idx)
			break;
		i++;
	}

	dlist_foreach_container(&lp->lp_avs, struct lnx_peer_av_info,
				pai, pai_entry) {
		if (pai->pai_av == pei->pei_cep->cep_cav) {
			pai_found = true;
			break;
		}
	}

	if (!pai_found)
		return -FI_ENOENT;

	lp->lp_peer_rr++;
	idx = lp->lp_peer_rr % (pai->pai_idx + 1);

	core_av_addrs = ofi_bufpool_get_ibuf(pei->pei_cep->cep_cav->cav_map, lp->lp_addr);
	*core_addr = core_av_addrs[idx];
	*cep_out = pei->pei_cep;

	return FI_SUCCESS;
}

#endif /* LNX_H */
