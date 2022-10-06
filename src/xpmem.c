/*
 * (C) Copyright 2022 Oak Ridge National Lab
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

#include <rdma/fi_errno.h>
#include "ofi_hmem.h"
#include "ofi.h"
#include <stdio.h>

#if HAVE_XPMEM
#include <ofi_xpmem.h>

#define XPMEM_DEFAULT_MEMCPY_CHUNK_SIZE 262144
struct xpmem *xpmem;

int xpmem_init(void)
{
	/* Any attachment that goes past the Linux TASK_SIZE will always
	 * fail. To prevent this we need to determine the value of
	 * TASK_SIZE. On x86_64 the value was hard-coded in sm to be
	 * 0x7ffffffffffful but this approach does not work with AARCH64
	 * (and possibly other architectures). Since there is really no
	 * way to directly determine the value we can (in all cases?) look
	 * through the mapping for this process to determine what the
	 * largest address is.  This should be the top of the stack. No
	 * heap allocations should be larger than this value.  Since the
	 * largest address may differ between processes the value must be
	 * shared as part of the modex and stored in the endpoint. */
	int ret = 0;
	char buffer[1024];
	uintptr_t address_max = 0;
	FILE *fh;

	fi_param_define(&core_prov, "use_xpmem", FI_PARAM_BOOL,
			"Whether to use XPMEM over CMA when possible "
			"(default: no)");
	fi_param_define(&core_prov, "xpmem_memcpy_chunksize", FI_PARAM_SIZE_T,
			"Maximum size used for a single memcpy call"
			"(default: %d)", XPMEM_DEFAULT_MEMCPY_CHUNK_SIZE);

	xpmem = calloc(sizeof(*xpmem), 1);
	if (!xpmem)
		return -FI_ENOMEM;

	fh = fopen("/proc/self/maps", "r");
	if (NULL == fh) {
		FI_WARN(&core_prov, FI_LOG_CORE,
				"could not open /proc/self/maps for reading");
		ret = -FI_EIO;
		goto fail;
	}

	while (fgets(buffer, sizeof(buffer), fh)) {
		uintptr_t low, high;
		char *tmp;
		/* each line of /proc/self/maps starts with low-high in
		 * hexidecimal (without a 0x) */
		low = strtoul(buffer, &tmp, 16);
		high = strtoul(tmp + 1, NULL, 16);
		if (address_max < high) {
			address_max = high;
		}
	}
	fclose(fh);

	if (address_max == 0) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"could not determine the address max");
		ret = -FI_EIO;
		goto fail;
	}

	/* save the calcuated maximum */
	xpmem->pinfo.address_max = address_max - 1;

	/* export the process virtual address space for use with xpmem */
	xpmem->pinfo.seg_id = xpmem_make(0, XPMEM_MAXADDR_SIZE, XPMEM_PERMIT_MODE,
					 (void *) 0666);
	if (xpmem->pinfo.seg_id == -1) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to export process virtual address space for use with xpmem\n");
		ret = -FI_ENODATA;
		goto fail;
	}

	ret = fi_param_get_size_t(&core_prov, "xpmem_memcpy_chunksize",
				  &xpmem->memcpy_chunk_size);
	if (ret)
		xpmem->memcpy_chunk_size = XPMEM_DEFAULT_MEMCPY_CHUNK_SIZE;

	return 0;

fail:
	free(xpmem);
	xpmem = NULL;
	return ret;
}

int xpmem_cleanup(void)
{
	int ret = 0;

	if (xpmem)
		ret = xpmem_remove(xpmem->pinfo.seg_id);

	return (ret) ? -FI_EINVAL : ret;
}

static inline void xpmem_memcpy(void *dst, void *src, size_t size)
{
	while (size > 0) {
		size_t copy_size = MIN(size, xpmem->memcpy_chunk_size);
		memcpy(dst, src, copy_size);
		dst = (void *) ((uintptr_t) dst + copy_size);
		src = (void *) ((uintptr_t) src + copy_size);
		size -= copy_size;
	}
}

int xpmem_copy(struct ofi_mr_cache *cache, struct iovec *local,
	       unsigned long local_cnt, struct iovec *remote,
	       unsigned long remote_cnt, size_t total, uint64_t id,
	       bool write)
{
	int ret, i;
	struct iovec iov;
	uint64_t offset, copy_len;
	ssize_t copy_ret;
	void *mapped_addr;
	struct smr_domain *domain;
	struct ofi_mr_entry *mr_entry;
	long page_size = ofi_get_page_size();

	domain = container_of(ep->util_ep.domain, struct smr_domain,
			      util_domain);

	assert(local_cnt == remote_cnt);

	for (i = 0; i < remote_cnt; i++) {
		iov.iov_base = (uintptr_t) ofi_get_page_start(remote[i].iov_base,
							page_size);
		iov.iov_len =
		  (uintptr_t) ofi_get_page_end(remote[i].iov_base + remote[i].iov_len,
						   page_size) - iov.iov_base;
		offset = (uintptr_t)((uintptr_t) remote[i].iov_base - iov.iov_base);

		ret = ofi_xpmem_cache_search(domain->xpmem_cache, &iov,
					     id, &mr_entry);
		if (ret)
			return ret;

		mapped_addr = (char*) (uintptr_t)mr_entry->info.mapped_addr +
		  offset;

		copy_len = (local[i].iov_len <= iov.iov_len - offset) ?
		  local[i].iov_len : iov.iov_len - offset;

		if (write)
			copy_ret = xpmem_memcpy(mapped_addr,
						local[i].iov_base,
						copy_len);
		else
			copy_ret = xpmem_memcpy(local[i].iov_base,
						mapped_addr,
						copy_len);

		if (copy_ret != copy_len)
			return -FI_EIO;

		ofi_mr_cache_delete(domain->xpmem_cache, mr_entry);
	}

	return 0;
}

# else

int xpmem_init(void)
{
	return -FI_ENOSYS;
}

int xpmem_cleanup(void)
{
	return -FI_ENOSYS;
}

int xpmem_copy(struct ofi_mr_cache *cache, struct iovec *local,
	       unsigned long local_cnt, struct iovec *remote,
	       unsigned long remote_cnt, size_t total, uint64_t id,
	       bool write)
{
	return -FI_ENOSYS;
}

#endif /* HAVE_XPMEM */
