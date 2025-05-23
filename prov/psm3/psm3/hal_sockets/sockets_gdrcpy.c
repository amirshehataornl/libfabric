#ifdef PSM_SOCKETS
/*

  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2018 Intel Corporation.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  Contact Information:
  Intel Corporation, www.intel.com

  BSD LICENSE

  Copyright(c) 2018 Intel Corporation.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/
#include "psm_user.h"

#ifdef PSM_HAVE_GPU
#include "psm2_hal.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "ips_proto.h"
#include "ptl_ips/ips_expected_proto.h"

// flags=0 for send, 1 for recv
void *
psm3_sockets_gdr_convert_gpu_to_host_addr(unsigned long buf,
							 size_t size, int flags,
							 psm2_ep_t ep)
{
#ifdef RNDV_MOD
	void *host_addr_buf;
	uintptr_t pageaddr;
	uint64_t pagelen;

	PSM3_GPU_ROUNDUP_GDRCOPY(buf, size, &pageaddr, &pagelen);
	_HFI_VDBG("buf=%p size=%zu pageaddr=%p pagelen=%"PRIu64" flags=0x%x ep=%p\n",
		(void *)buf, size, (void *)pageaddr, pagelen, flags, ep);
	ep = ep->mctxt_master;
	host_addr_buf = psm3_rv_pin_and_mmap(ep->rv, pageaddr, pagelen, IBV_ACCESS_IS_GPU_ADDR);
	if_pf (! host_addr_buf) {
		if (errno == ENOMEM) {
			if (psm3_gpu_evict_some(ep, pagelen, IBV_ACCESS_IS_GPU_ADDR) > 0)
				host_addr_buf = psm3_rv_pin_and_mmap(ep->rv, pageaddr, pagelen, IBV_ACCESS_IS_GPU_ADDR);
		}
		if_pf (! host_addr_buf)
			return NULL;
	}
//_HFI_ERROR("pinned buf=%p size=%zu pageaddr=%p pagelen=%u flags=0x%x ep=%p, @ %p\n", (void *)buf, size, (void *)pageaddr, pagelen, flags, ep, host_addr_buf);
	return (void *)((uintptr_t)host_addr_buf + (buf - pageaddr));
#else
	psmi_assert_always(0);	// unimplemented, should not get here
	return NULL;
#endif /* RNDV_MOD */
}

#endif /* PSM_HAVE_GPU */
#endif /* PSM_SOCKETS */
