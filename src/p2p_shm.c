/*
 * (C) Copyright 2020 Hewlett Packard Enterprise Development LP
 * (C) Copyright 2020-2021 Intel Corporation. All rights reserved.
 * (C) Copyright 2021 Amazon.com, Inc. or its affiliates.
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "ofi_shm.h"
#include "ofi.h"
#include "ofi_iov.h"

struct ofi_shm_p2p_ops p2p_ops[] = {
	[FI_SHM_P2P_XPMEM] = {
		.init = ofi_shm_p2p_init_noop,
		.cleanup = ofi_shm_p2p_cleanup_noop,
		.copy = ofi_shm_p2p_copy_noop,
	},
	[FI_SHM_P2P_CMA] = {
		.init = ofi_shm_p2p_init_noop,
		.cleanup = ofi_shm_p2p_cleanup_noop,
		.copy = ofi_shm_p2p_copy_noop,
	},
	[FI_SHM_P2P_DSA] = {
		.init = ofi_shm_p2p_init_noop,
		.cleanup = ofi_shm_p2p_cleanup_noop,
		.copy = ofi_shm_p2p_copy_noop,
	},
};

int ofi_shm_p2p_init(enum ofi_shm_p2p_type p2p_type)
{
	return p2p_ops[p2p_type].init();
}

int ofi_shm_p2p_cleanup(enum ofi_shm_p2p_type p2p_type)
{
	return p2p_ops[p2p_type].cleanup();
}

int
ofi_shm_p2p_copy(enum ofi_shm_p2p_type p2p_type, struct ofi_mr_cache *cache,
		 struct iovec *local, unsigned long local_cnt,
		 struct iovec *remote, unsigned long remote_cnt, size_t total,
		 uint64_t id, bool write)
{
	return p2p_ops[p2p_type].copy(cache, local, local_cnt, remote,
				      remote_cnt, total, id, write);
}
