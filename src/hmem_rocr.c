/*
 * (C) Copyright 2020 Hewlett Packard Enterprise Development LP
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

#include "ofi_hmem.h"
#include "ofi_mem.h"
#include "ofi.h"

#if HAVE_ROCR

#define HSA_MAX_SIGNALS 512
#define DEVICE_THRESHOLD 524288
#define H2D_THRESHOLD 1048576

struct ofi_hsa_signal_info {
	hsa_signal_t sig;
	void *addr;
};

OFI_DECLARE_FREESTACK(struct ofi_hsa_signal_info, rocm_ipc_signal_fs);

struct rocm_ipc_signal_fs *ipc_signal_fs;

struct hsa_ops {
	hsa_status_t (*hsa_memory_copy)(void *dst, const void *src,
					size_t size);
	hsa_status_t (*hsa_amd_memory_async_copy)(void* dst, hsa_agent_t dst_agent,
					const void* src,
					hsa_agent_t src_agent, size_t size,
					uint32_t num_dep_signals,
					const hsa_signal_t* dep_signals,
					hsa_signal_t completion_signal);
	hsa_status_t (*hsa_amd_pointer_info)(void *ptr,
					     hsa_amd_pointer_info_t *info,
					     void *(*alloc)(size_t),
					     uint32_t *num_agents_accessible,
					     hsa_agent_t **accessible);
	hsa_status_t (*hsa_init)(void);
	hsa_status_t (*hsa_shut_down)(void);
	hsa_status_t (*hsa_status_string)(hsa_status_t status,
					  const char **status_string);
	hsa_status_t (*hsa_amd_dereg_dealloc_cb)(void *ptr,
						 hsa_amd_deallocation_callback_t cb);
	hsa_status_t (*hsa_amd_reg_dealloc_cb)(void *ptr,
					       hsa_amd_deallocation_callback_t cb,
					       void *user_data);
	hsa_status_t (*hsa_amd_memory_lock)(void *host_ptr, size_t size,
					    hsa_agent_t *agents, int num_agents,
					    void **agent_ptr);
	hsa_status_t (*hsa_amd_memory_unlock)(void *host_ptr);
	hsa_status_t (*hsa_agent_get_info)(hsa_agent_t agent,
					   hsa_agent_info_t attribute,
					   void *value);
	hsa_status_t (*hsa_amd_ipc_memory_create)(void* ptr, size_t len,
					hsa_amd_ipc_memory_t* handle);
	hsa_status_t (*hsa_amd_ipc_memory_attach)(
		const hsa_amd_ipc_memory_t* handle, size_t len,
		uint32_t num_agents,
		const hsa_agent_t* mapping_agents,
		void** mapped_ptr);
	hsa_status_t (*hsa_amd_ipc_memory_detach)(void* mapped_ptr);
	void (*hsa_signal_store_screlease)(hsa_signal_t signal,
							hsa_signal_value_t value);
	hsa_signal_value_t (*hsa_signal_load_scacquire)(hsa_signal_t signal);
	hsa_status_t (*hsa_amd_agents_allow_access)(uint32_t num_agents,
								const hsa_agent_t* agents,
								const uint32_t* flags, const void* ptr);
	hsa_status_t (*hsa_signal_create)(hsa_signal_value_t initial_value,
									  uint32_t num_consumers,
									  const hsa_agent_t *consumers,
									  hsa_signal_t *signal);
	hsa_status_t (*hsa_signal_destroy)(hsa_signal_t signal);
};

#if ENABLE_ROCR_DLOPEN

#include <dlfcn.h>

static void *hsa_handle;
static struct hsa_ops hsa_ops;

#else

static struct hsa_ops hsa_ops = {
	/* mem copy ops */
	.hsa_memory_copy = hsa_memory_copy,
	/* Asynchronously copy a block of memory from the location pointed to by
	 * src on the src_agent to the memory block pointed to by dst on the
	 * dst_agent. */
	.hsa_amd_memory_async_copy = hsa_amd_memory_async_copy,
	/* gets information about the device mem pointer */
	.hsa_amd_pointer_info = hsa_amd_pointer_info,
	/* initialize the runt time library */
	.hsa_init = hsa_init,
	.hsa_shut_down = hsa_shut_down,
	.hsa_status_string = hsa_status_string,
	/* used for memory monitoring */
	.hsa_amd_dereg_dealloc_cb =
		hsa_amd_deregister_deallocation_callback,
	.hsa_amd_reg_dealloc_cb =
		hsa_amd_register_deallocation_callback,
	/* memory lock/unlock used for registration */
	.hsa_amd_memory_lock = hsa_amd_memory_lock,
	.hsa_amd_memory_unlock = hsa_amd_memory_unlock,
	.hsa_agent_get_info = hsa_agent_get_info,
	/* Prepares an allocation for interprocess sharing and creates a
	 * handle of type hsa_amd_ipc_memory_t uniquely identifying the
	 * allocation. */
	.hsa_amd_ipc_memory_create = hsa_amd_ipc_memory_create,
	/* Imports shared memory into the local process and makes it accessible
	 * by the given agents. */
	.hsa_amd_ipc_memory_attach = hsa_amd_ipc_memory_attach,
	/* Decrements the reference count for the shared memory mapping and
	 * releases access to shared memory imported with
	 * hsa_amd_ipc_memory_attach */
	.hsa_amd_ipc_memory_detach = hsa_amd_ipc_memory_detach,
	.hsa_signal_store_screlease = hsa_signal_store_screlease,
	.hsa_signal_load_scacquire = hsa_signal_load_scacquire,
	.hsa_amd_agents_allow_access = hsa_amd_agents_allow_access,
	.hsa_signal_create = hsa_signal_create,
	.hsa_signal_destroy = hsa_signal_destroy,
};

#endif /* ENABLE_ROCR_DLOPEN */

static hsa_status_t
ofi_hsa_amd_agents_allow_access(uint32_t num_agents, const hsa_agent_t* agents,
								const uint32_t* flags, const void* ptr)
{
	return hsa_ops.hsa_amd_agents_allow_access(num_agents, agents, flags,
											   ptr);
}

static void
ofi_hsa_signal_store_screlease(hsa_signal_t signal, hsa_signal_value_t value)
{
	hsa_ops.hsa_signal_store_screlease(signal, value);
}

static hsa_signal_value_t ofi_hsa_signal_load_scacquire(hsa_signal_t signal)
{
	return hsa_ops.hsa_signal_load_scacquire(signal);
}

static void ofi_hsa_signal_create(struct ofi_hsa_signal_info *info, void *arg)
{
	hsa_status_t hsa_ret;

	if ((hsa_ret = hsa_ops.hsa_signal_create(1, 0, NULL, &info->sig) !=
		HSA_STATUS_SUCCESS)) {
		FI_WARN(&core_prov, FI_LOG_CORE,
				"Failed to perform hsa_signal_create: %s\n",
				ofi_hsa_status_to_string(hsa_ret));
	}
}

static void ofi_hsa_signal_destroy(struct ofi_hsa_signal_info *info, void *arg)
{
	hsa_status_t hsa_ret;

	if ((hsa_ret = hsa_ops.hsa_signal_destroy(info->sig) !=
		HSA_STATUS_SUCCESS)) {
		FI_WARN(&core_prov, FI_LOG_CORE,
				"Failed to perform hsa_signal_destroy: %s\n",
				ofi_hsa_status_to_string(hsa_ret));
	}
}

hsa_status_t ofi_hsa_amd_memory_lock(void *host_ptr, size_t size,
				     hsa_agent_t *agents, int num_agents,
				     void **agent_ptr)
{
	return hsa_ops.hsa_amd_memory_lock(host_ptr, size, agents, num_agents,
					    agent_ptr);
}

hsa_status_t ofi_hsa_amd_memory_unlock(void *host_ptr)
{
	return hsa_ops.hsa_amd_memory_unlock(host_ptr);
}

hsa_status_t ofi_hsa_memory_copy(void *dst, const void *src, size_t size)
{
	return hsa_ops.hsa_memory_copy(dst, src, size);
}

hsa_status_t ofi_hsa_amd_memory_async_copy(void* dst, hsa_agent_t dst_agent,
					const void* src,
					hsa_agent_t src_agent, size_t size,
					uint32_t num_dep_signals,
					const hsa_signal_t* dep_signals,
					hsa_signal_t completion_signal)
{
	return hsa_ops.hsa_amd_memory_async_copy(dst, dst_agent,
				src, src_agent, size, num_dep_signals,
				dep_signals, completion_signal);
}

hsa_status_t ofi_hsa_amd_pointer_info(void *ptr, hsa_amd_pointer_info_t *info,
				      void *(*alloc)(size_t),
				      uint32_t *num_agents_accessible,
				      hsa_agent_t **accessible)
{
	return hsa_ops.hsa_amd_pointer_info(ptr, info, alloc,
					     num_agents_accessible, accessible);
}

hsa_status_t ofi_hsa_init(void)
{
	return hsa_ops.hsa_init();
}

hsa_status_t ofi_hsa_shut_down(void)
{
	return hsa_ops.hsa_shut_down();
}

hsa_status_t ofi_hsa_status_string(hsa_status_t status,
				   const char **status_string)
{
	return hsa_ops.hsa_status_string(status, status_string);
}

const char *ofi_hsa_status_to_string(hsa_status_t status)
{
	const char *str;
	hsa_status_t hsa_ret;

	hsa_ret = ofi_hsa_status_string(status, &str);
	if (hsa_ret != HSA_STATUS_SUCCESS)
		return "unknown error";

	return str;
}

hsa_status_t ofi_hsa_amd_dereg_dealloc_cb(void *ptr,
					  hsa_amd_deallocation_callback_t cb)
{
	return hsa_ops.hsa_amd_dereg_dealloc_cb(ptr, cb);
}

hsa_status_t ofi_hsa_amd_reg_dealloc_cb(void *ptr,
					hsa_amd_deallocation_callback_t cb,
					void *user_data)
{
	return hsa_ops.hsa_amd_reg_dealloc_cb(ptr, cb, user_data);
}

static hsa_status_t ofi_hsa_agent_get_info(hsa_agent_t agent,
					   hsa_agent_info_t attribute,
					   void *value)
{
	return hsa_ops.hsa_agent_get_info(agent, attribute, value);
}

static int rocr_memcpy(void *dest, const void *src, size_t size)
{
	hsa_status_t hsa_ret;

	hsa_ret = ofi_hsa_memory_copy(dest, src, size);
	if (hsa_ret == HSA_STATUS_SUCCESS)
		return 0;

	FI_WARN(&core_prov, FI_LOG_CORE,
		"Failed to perform hsa_memory_copy: %s\n",
		ofi_hsa_status_to_string(hsa_ret));

	return -FI_EIO;
}

static int rocr_host_memory_ptr(void *host_ptr, void **ptr,
								hsa_agent_t *agent, size_t *size,
								uint64_t *offset, bool *system)
{
	hsa_amd_pointer_info_t info = {
		.size = sizeof(info),
	};
	hsa_status_t hsa_ret;

	if (system)
		*system = false;

	hsa_ret = ofi_hsa_amd_pointer_info((void *)host_ptr, &info, NULL, NULL,
					   NULL);
	if (hsa_ret != HSA_STATUS_SUCCESS) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to perform hsa_amd_pointer_info: %s\n",
			ofi_hsa_status_to_string(hsa_ret));

		return -FI_EIO;
	}

	if (agent)
		*agent = info.agentOwner;

	if (size)
		*size = info.sizeInBytes;

	if (info.type != HSA_EXT_POINTER_TYPE_LOCKED) {
		if (info.type == HSA_EXT_POINTER_TYPE_IPC ||
			info.type == HSA_EXT_POINTER_TYPE_HSA)
			*ptr = info.agentBaseAddress;
		else
			*ptr = host_ptr;

		if (info.type == HSA_EXT_POINTER_TYPE_UNKNOWN && system)
			*system = true;
		if (offset)
			*offset = host_ptr - *ptr;
	} else {
		*ptr = (void *) ((uintptr_t) info.agentBaseAddress +
				 (uintptr_t) host_ptr -
				 (uintptr_t) info.hostBaseAddress);
		if (system)
			*system = true;
	}

	return FI_SUCCESS;
}

int rocr_copy_from_dev(uint64_t device, void *dest, const void *src,
		       size_t size)
{
	int ret;
	void *dest_memcpy_ptr;

	ret = rocr_host_memory_ptr(dest, &dest_memcpy_ptr, NULL, NULL, NULL,
							   NULL);

	if (ret != FI_SUCCESS)
		return ret;

	ret = rocr_memcpy(dest_memcpy_ptr, src, size);

	return ret;
}

int rocr_copy_to_dev(uint64_t device, void *dest, const void *src,
		     size_t size)
{
	int ret;
	void *src_memcpy_ptr;
	size_t h2d_thresh;

	if (fi_param_get_size_t(&core_prov, "rocr_h2d_threshold",
						&h2d_thresh) < 0)
		h2d_thresh = H2D_THRESHOLD;

	if (size <= h2d_thresh) {
		memcpy(dest, src, size);
		return FI_SUCCESS;
	}

	ret = rocr_host_memory_ptr((void *) src, &src_memcpy_ptr, NULL, NULL,
							   NULL, NULL);
	if (ret != FI_SUCCESS)
		return ret;

	ret = rocr_memcpy(dest, src_memcpy_ptr, size);

	return ret;
}

static int
rocr_dev_async_copy(void *dst, const void *src, size_t size,
					void **ostream)
{
	void *src_hsa_ptr;
	void *dst_hsa_ptr;
	int ret;
	hsa_status_t hsa_ret;
	struct ofi_hsa_signal_info *ipc_signal;
	/* 0 - source agent
	 * 1 - destination agent
	 */
	hsa_agent_t agents[2];
	bool src_local, dst_local;

	if (!ostream)
		return -FI_EINVAL;

	ret = rocr_host_memory_ptr((void *)src, &src_hsa_ptr, &agents[0], NULL, NULL,
							   &src_local);
	if (ret != FI_SUCCESS)
		return ret;

	ret = rocr_host_memory_ptr(dst, &dst_hsa_ptr, &agents[1], NULL, NULL,
							   &dst_local);
	if (ret != FI_SUCCESS)
		return ret;

	ipc_signal = ofi_freestack_pop(ipc_signal_fs);
	/* device to device */
	if (!src_local && !dst_local) {
		hsa_ret = ofi_hsa_amd_agents_allow_access(2, agents, NULL, dst_hsa_ptr);
		if (hsa_ret != HSA_STATUS_SUCCESS) {
			FI_WARN(&core_prov, FI_LOG_CORE,
					"Failed to perform hsa_amd_agents_allow_access %s\n",
					ofi_hsa_status_to_string(hsa_ret));
			ret = -FI_EINVAL;
			goto fail;
		}
		ipc_signal->addr = NULL;
	/* device to host */
	} else if (!src_local && dst_local) {
		hsa_ret = ofi_hsa_amd_memory_lock(dst, size, NULL, 0, &dst_hsa_ptr);
		if (hsa_ret != HSA_STATUS_SUCCESS) {
			ret = -FI_EINVAL;
			goto fail;
		}
		ipc_signal->addr = dst;
		agents[1] = agents[0];
	}

	ofi_hsa_signal_store_screlease(ipc_signal->sig, 1);

	hsa_ret = ofi_hsa_amd_memory_async_copy(dst_hsa_ptr, agents[1],
								src_hsa_ptr, agents[0],
								size, 0, NULL, ipc_signal->sig);

	if (hsa_ret != HSA_STATUS_SUCCESS) {
		FI_WARN(&core_prov, FI_LOG_CORE,
				"Failed to perform hsa_amd_memory_async_copy %s\n",
				ofi_hsa_status_to_string(hsa_ret));
		ret = -FI_EINVAL;
		goto fail;
	}

	*ostream = ipc_signal;

	return 0;

fail:
	ofi_freestack_push(ipc_signal_fs, ipc_signal);
	return ret;
}

int rocr_async_copy_to_dev(uint64_t device, void *dst, const void *src,
						size_t size, void *istream, void **ostream)
{
	return rocr_dev_async_copy(dst, src, size, ostream);
}

int rocr_async_copy_from_dev(uint64_t device, void *dst, const void *src,
						size_t size, void *istream, void **ostream)
{
	return rocr_dev_async_copy(dst, src, size, ostream);
}

int rocr_async_copy_query(void *stream)
{
	struct ofi_hsa_signal_info *ipc_signal = stream;
	hsa_signal_value_t v;

	v = ofi_hsa_signal_load_scacquire(ipc_signal->sig);
	if (v != 0)
		return -FI_EBUSY;

	if (ipc_signal->addr)
		ofi_hsa_amd_memory_unlock(ipc_signal->addr);
	ofi_freestack_push(ipc_signal_fs, ipc_signal);

	return FI_SUCCESS;
}

bool rocr_is_addr_valid(const void *addr, uint64_t *device, uint64_t *flags)
{
	hsa_amd_pointer_info_t hsa_info = {
		.size = sizeof(hsa_info),
	};
	hsa_device_type_t hsa_dev_type;
	hsa_status_t hsa_ret;

	hsa_ret = ofi_hsa_amd_pointer_info((void *)addr, &hsa_info, NULL, NULL,
					   NULL);
	if (hsa_ret == HSA_STATUS_SUCCESS) {
		hsa_ret = ofi_hsa_agent_get_info(hsa_info.agentOwner,
						 HSA_AGENT_INFO_DEVICE,
						 (void *) &hsa_dev_type);
		if (hsa_ret == HSA_STATUS_SUCCESS) {
			if (hsa_dev_type == HSA_DEVICE_TYPE_GPU) {
				//TODO get device pointer/id
				if (flags)
					*flags = FI_HMEM_DEVICE_ONLY;
				return true;
			}
		} else {
			FI_WARN(&core_prov, FI_LOG_CORE,
				"Failed to perform hsa_agent_get_info: %s\n",
				ofi_hsa_status_to_string(hsa_ret));
		}
	} else {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to perform hsa_amd_pointer_info: %s\n",
			ofi_hsa_status_to_string(hsa_ret));
	}

	return false;
}

int rocr_get_ipc_handle_size(size_t *size)
{
	*size = sizeof(hsa_amd_ipc_memory_t);
	return FI_SUCCESS;
}

int rocr_get_async_copy_cutoff(size_t *size)
{
	size_t cpy_thresh = DEVICE_THRESHOLD;

	fi_param_get_size_t(&core_prov, "rocr_device_threshold",
						&cpy_thresh);

	*size = cpy_thresh;

	return FI_SUCCESS;
}

int rocr_get_base_addr(const void *ptr, void **base, size_t *size)
{
	return rocr_host_memory_ptr((void*)ptr, base, NULL, size, NULL, NULL);
}

int rocr_get_handle(void *dev_buf, size_t size, void **handle)
{
	hsa_status_t hsa_ret;

	hsa_ret = hsa_ops.hsa_amd_ipc_memory_create(dev_buf, size,
				(hsa_amd_ipc_memory_t *)handle);

	if (hsa_ret == HSA_STATUS_SUCCESS)
		return FI_SUCCESS;

	FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to perform hsa_amd_ipc_memory_create: %s\n",
			ofi_hsa_status_to_string(hsa_ret));

	return -FI_EINVAL;
}

int rocr_open_handle(void **handle, size_t len, uint64_t device, void **ipc_ptr)
{
	hsa_status_t hsa_ret;

	hsa_ret = hsa_ops.hsa_amd_ipc_memory_attach((hsa_amd_ipc_memory_t *)handle,
					len, 0, NULL, ipc_ptr);
	if (hsa_ret == HSA_STATUS_SUCCESS)
		return FI_SUCCESS;

	FI_WARN(&core_prov, FI_LOG_CORE,
		"Failed to perform hsa_amd_ipc_memory_attach: %s\n",
		ofi_hsa_status_to_string(hsa_ret));

	return -FI_EINVAL;
}

int rocr_close_handle(void *ipc_ptr)
{
	hsa_status_t hsa_ret;

	hsa_ret = hsa_ops.hsa_amd_ipc_memory_detach(ipc_ptr);

	if (hsa_ret == HSA_STATUS_SUCCESS)
		return FI_SUCCESS;

	FI_WARN(&core_prov, FI_LOG_CORE,
		"Failed to perform hsa_amd_ipc_memory_detach: %s\n",
		ofi_hsa_status_to_string(hsa_ret));

	return -FI_EINVAL;
}

bool rocr_is_ipc_enabled(void)
{
	return !ofi_hmem_p2p_disabled();
}

static int rocr_hmem_dl_init(void)
{
#if ENABLE_ROCR_DLOPEN
	/* Assume if dlopen fails, the ROCR library could not be found. Do not
	 * treat this as an error.
	 */
	hsa_handle = dlopen("libhsa-runtime64.so", RTLD_NOW);
	if (!hsa_handle) {
		FI_INFO(&core_prov, FI_LOG_CORE,
			"Unable to dlopen libhsa-runtime64.so\n");
		return -FI_ENOSYS;
	}

	hsa_ops.hsa_memory_copy = dlsym(hsa_handle, "hsa_memory_copy");
	if (!hsa_ops.hsa_memory_copy) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_memory_copy\n");
		goto err;
	}

	hsa_ops.hsa_amd_memory_async_copy = dlsym(hsa_handle, "hsa_amd_memory_async_copy");
	if (!hsa_ops.hsa_amd_memory_async_copy) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_amd_memory_async_copy\n");
		goto err;
	}

	hsa_ops.hsa_amd_pointer_info = dlsym(hsa_handle,
					      "hsa_amd_pointer_info");
	if (!hsa_ops.hsa_amd_pointer_info) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_amd_pointer_info\n");
		goto err;
	}

	hsa_ops.hsa_init = dlsym(hsa_handle, "hsa_init");
	if (!hsa_ops.hsa_init) {
		FI_WARN(&core_prov, FI_LOG_CORE, "Failed to find hsa_init\n");
		goto err;
	}

	hsa_ops.hsa_shut_down = dlsym(hsa_handle, "hsa_shut_down");
	if (!hsa_ops.hsa_shut_down) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_shut_down\n");
		goto err;
	}

	hsa_ops.hsa_status_string = dlsym(hsa_handle, "hsa_status_string");
	if (!hsa_ops.hsa_status_string) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_status_string\n");
		goto err;
	}

	hsa_ops.hsa_amd_dereg_dealloc_cb =
		dlsym(hsa_handle, "hsa_amd_deregister_deallocation_callback");
	if (!hsa_ops.hsa_amd_dereg_dealloc_cb) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_amd_deregister_deallocation_callback\n");
		goto err;
	}

	hsa_ops.hsa_amd_reg_dealloc_cb =
		dlsym(hsa_handle, "hsa_amd_register_deallocation_callback");
	if (!hsa_ops.hsa_amd_reg_dealloc_cb) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_amd_register_deallocation_callback\n");
		goto err;
	}

	hsa_ops.hsa_amd_memory_lock = dlsym(hsa_handle,
					     "hsa_amd_memory_lock");
	if (!hsa_ops.hsa_amd_memory_lock) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_amd_memory_lock\n");
		goto err;
	}

	hsa_ops.hsa_amd_memory_unlock = dlsym(hsa_handle,
					       "hsa_amd_memory_unlock");
	if (!hsa_ops.hsa_amd_memory_unlock) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_amd_memory_unlock\n");
		goto err;
	}

	hsa_ops.hsa_agent_get_info = dlsym(hsa_handle, "hsa_agent_get_info");
	if (!hsa_ops.hsa_agent_get_info) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_agent_get_info\n");
		goto err;
	}

	hsa_ops.hsa_amd_ipc_memory_create= dlsym(hsa_handle, "hsa_amd_ipc_memory_create");
	if (!hsa_ops.hsa_amd_ipc_memory_create) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_amd_ipc_memory_create\n");
		goto err;
	}

	hsa_ops.hsa_amd_ipc_memory_attach = dlsym(hsa_handle, "hsa_amd_ipc_memory_attach");
	if (!hsa_ops.hsa_amd_ipc_memory_attach) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_amd_ipc_memory_attach\n");
		goto err;
	}

	hsa_ops.hsa_amd_ipc_memory_detach = dlsym(hsa_handle, "hsa_amd_ipc_memory_detach");
	if (!hsa_ops.hsa_amd_ipc_memory_detach) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_amd_ipc_memory_detach\n");
		goto err;
	}

	hsa_ops.hsa_signal_create = dlsym(hsa_handle, "hsa_signal_create");
	if (!hsa_ops.hsa_signal_create) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_signal_create\n");
		goto err;
	}

	hsa_ops.hsa_signal_destroy = dlsym(hsa_handle, "hsa_signal_destroy");
	if (!hsa_ops.hsa_signal_destroy) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to find hsa_signal_destroy\n");
		goto err;
	}

	return FI_SUCCESS;

err:
	dlclose(hsa_handle);

	return -FI_ENODATA;
#else
	return FI_SUCCESS;
#endif /* ENABLE_ROCR_DLOPEN */
}

static void rocr_hmem_dl_cleanup(void)
{
#if ENABLE_ROCR_DLOPEN
	dlclose(hsa_handle);
#endif
}

int rocr_hmem_init(void)
{
	hsa_status_t hsa_ret;
	int ret;
	int log_level;

	fi_param_define(NULL, "rocr_d2d_threshold", FI_PARAM_SIZE_T,
			"Threshold for switching to hsa memcpy for device-to-host copies."
			" (Default 16384");

	fi_param_define(NULL, "rocr_device_threshold", FI_PARAM_SIZE_T,
			"Threshold for switching to hsa memcpy for device-to-host copies."
			" (Default 16384");

	fi_param_define(NULL, "rocr_h2d_threshold", FI_PARAM_SIZE_T,
			"Threshold for switching to hsa memcpy for host-to-device copies."
			" (Default 1048576");

	ret = rocr_hmem_dl_init();
	if (ret != FI_SUCCESS)
		return ret;

	hsa_ret = ofi_hsa_init();
	if (hsa_ret != HSA_STATUS_SUCCESS)
		goto fail;

	ipc_signal_fs = rocm_ipc_signal_fs_create(HSA_MAX_SIGNALS, ofi_hsa_signal_create, NULL);
	if (!ipc_signal_fs)
		goto fail;

	return 0;

fail:
	/* Treat HSA_STATUS_ERROR_OUT_OF_RESOURCES as ROCR not being supported
	 * instead of an error. This ROCR error is typically returned if no
	 * devices are supported.
	 */
	if (hsa_ret == HSA_STATUS_ERROR_OUT_OF_RESOURCES) {
		log_level = FI_LOG_INFO;
		ret = -FI_ENOSYS;
	} else {
		log_level = FI_LOG_WARN;
		ret = -FI_EIO;
	}

	FI_LOG(&core_prov, log_level, FI_LOG_CORE,
	       "Failed to perform hsa_init: %s\n",
	       ofi_hsa_status_to_string(hsa_ret));

	rocr_hmem_dl_cleanup();

	return ret;
}

int rocr_hmem_cleanup(void)
{
	hsa_status_t hsa_ret;

	rocm_ipc_signal_fs_destroy(ipc_signal_fs, HSA_MAX_SIGNALS,
							   ofi_hsa_signal_destroy, NULL);

	hsa_ret = ofi_hsa_shut_down();
	if (hsa_ret != HSA_STATUS_SUCCESS) {
		FI_WARN(&core_prov, FI_LOG_CORE,
			"Failed to perform hsa_shut_down: %s\n",
			ofi_hsa_status_to_string(hsa_ret));
		return -FI_ENODATA;
	}

	rocr_hmem_dl_cleanup();

	return FI_SUCCESS;
}

int rocr_host_register(void *ptr, size_t size)
{
	hsa_status_t hsa_ret;
	void *tmp;

	hsa_ret = ofi_hsa_amd_memory_lock(ptr, size, NULL, 0, &tmp);
	if (hsa_ret == HSA_STATUS_SUCCESS)
		return FI_SUCCESS;

	FI_WARN(&core_prov, FI_LOG_CORE,
		"Failed to perform hsa_amd_memory_lock: %s\n",
		ofi_hsa_status_to_string(hsa_ret));

	return -FI_EIO;
}

int rocr_host_unregister(void *ptr)
{
	hsa_status_t hsa_ret;

	hsa_ret = ofi_hsa_amd_memory_unlock(ptr);
	if (hsa_ret == HSA_STATUS_SUCCESS)
		return FI_SUCCESS;

	FI_WARN(&core_prov, FI_LOG_CORE,
		"Failed to perform hsa_amd_memory_unlock: %s\n",
		ofi_hsa_status_to_string(hsa_ret));

	return -FI_EIO;
}

#else

int rocr_copy_from_dev(uint64_t device, void *dest, const void *src,
		       size_t size)
{
	return -FI_ENOSYS;
}

int rocr_copy_to_dev(uint64_t device, void *dest, const void *src,
		     size_t size)
{
	return -FI_ENOSYS;
}

int rocr_hmem_init(void)
{
	return -FI_ENOSYS;
}

int rocr_hmem_cleanup(void)
{
	return -FI_ENOSYS;
}

bool rocr_is_addr_valid(const void *addr, uint64_t *device, uint64_t *flags)
{
	return false;
}

int rocr_host_register(void *ptr, size_t size)
{
	return -FI_ENOSYS;
}

int rocr_host_unregister(void *ptr)
{
	return -FI_ENOSYS;
}

int rocr_get_handle(void *dev_buf, size_t size, void **handle)
{
	return -FI_ENOSYS;
}

int rocr_open_handle(void **handle, size_t len, uint64_t device, void **ipc_ptr)
{
	return -FI_ENOSYS;
}

int rocr_close_handle(void *ipc_ptr)
{
	return -FI_ENOSYS;
}

bool rocr_is_ipc_enabled(void)
{
	return false;
}

int rocr_get_ipc_handle_size(size_t *size)
{
	return -FI_ENOSYS;
}

int rocr_get_base_addr(const void *ptr, void **base, size_t *size)
{
	return -FI_ENOSYS;
}

int rocr_async_copy_to_dev(uint64_t device, void *dst, const void *src,
						size_t size, void *istream, void **ostream)
{
	return -FI_ENOSYS;
}

int rocr_async_copy_from_dev(uint64_t device, void *dst, const void *src,
						size_t size, void *istream, void **ostream)
{
	return -FI_ENOSYS;
}

int rocr_async_copy_query(void *stream)
{
	return -FI_ENOSYS;
}

int rocr_get_async_copy_cutoff(size_t *size)
{
	return -FI_ENOSYS;
}

#endif /* HAVE_ROCR */
