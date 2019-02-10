/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Contact Information:
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
 *
 * BSD LICENSE
 *
 * Copyright(c) 2016 Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors:
 *
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 * Serge Ayoun <serge.ayoun@intel.com>
 * Shay Katz-zamir <shay.katz-zamir@intel.com>
 * Sean Christopherson <sean.j.christopherson@intel.com>
 */

#include "sgx.h"
#include <linux/acpi.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/hashtable.h>
#include <linux/kthread.h>
#include <linux/platform_device.h>

#define DRV_DESCRIPTION "Intel SGX Driver (Dummy)"
#define DRV_VERSION "0.10"

// Hard-coding EPC address and size
#define EPC_ADDR	(0x80200000)
#define EPC_SIZE	(0x5d80000)

#define ENCL_SIZE_MAX_64 (64ULL * 1024ULL * 1024ULL * 1024ULL)
#define ENCL_SIZE_MAX_32 (2ULL * 1024ULL * 1024ULL * 1024ULL)

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR("Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>");
MODULE_VERSION(DRV_VERSION);
#ifndef X86_FEATURE_SGX
#define X86_FEATURE_SGX (9 * 32 + 2)
#endif

/*
 * Global data.
 */

struct workqueue_struct *sgx_add_page_wq;
#define SGX_MAX_EPC_BANKS 8
struct sgx_epc_bank sgx_epc_banks[SGX_MAX_EPC_BANKS];
int sgx_nr_epc_banks;
u64 sgx_encl_size_max_32 = ENCL_SIZE_MAX_32;
u64 sgx_encl_size_max_64 = ENCL_SIZE_MAX_64;
u64 sgx_xfrm_mask = 0x3;
u32 sgx_ssaframesize_tbl[64];
bool sgx_has_sgx2;

#ifdef CONFIG_COMPAT
long sgx_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	return sgx_ioctl(filep, cmd, arg);
}
#endif

static int sgx_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &sgx_vm_ops;
	vma->vm_flags |= VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_IO |
			 VM_DONTCOPY;

	return 0;
}

static unsigned long sgx_get_unmapped_area(struct file *file,
					   unsigned long addr,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags)
{
	if (len < 2 * PAGE_SIZE || (len & (len - 1)))
		return -EINVAL;

	/* On 64-bit architecture, allow mmap() to exceed 32-bit encl
	 * limit only if the task is not running in 32-bit compatibility
	 * mode.
	 */
	if (len > sgx_encl_size_max_32)
#ifdef CONFIG_X86_64
		if (test_thread_flag(TIF_ADDR32))
			return -EINVAL;
#else
		return -EINVAL;
#endif

#ifdef CONFIG_X86_64
	if (len > sgx_encl_size_max_64)
		return -EINVAL;
#endif

	addr = current->mm->get_unmapped_area(file, addr, 2 * len, pgoff,
					      flags);
	if (IS_ERR_VALUE(addr))
		return addr;

	addr = (addr + (len - 1)) & ~(len - 1);

	return addr;
}

static const struct file_operations sgx_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= sgx_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= sgx_compat_ioctl,
#endif
	.mmap			= sgx_mmap,
	.get_unmapped_area	= sgx_get_unmapped_area,
};

static struct miscdevice sgx_dev = {
	.name	= "isgx-dummy",
	.fops	= &sgx_fops,
	.mode   = 0666,
};

static __init int sgx_init(void)
{
	unsigned int wq_flags;
	int ret;
	int i;

	pr_info("intel_sgx: " DRV_DESCRIPTION " v" DRV_VERSION "\n");

	// hard-coded (from a real sgx machine)
	sgx_nr_epc_banks = 1;
	sgx_epc_banks[0].start = EPC_ADDR;
	sgx_epc_banks[0].end = EPC_ADDR + EPC_SIZE;

	pr_info("intel_sgx: Number of EPCs %d\n", sgx_nr_epc_banks);

	for (i = 0; i < sgx_nr_epc_banks; i++) {
		pr_info("intel_sgx: EPC memory range 0x%lx-0x%lx\n",
			sgx_epc_banks[i].start, sgx_epc_banks[i].end);
#ifdef CONFIG_X86_64
		sgx_epc_banks[i].mem = ioremap_cache(sgx_epc_banks[i].start,
			sgx_epc_banks[i].end - sgx_epc_banks[i].start);
		if (!sgx_epc_banks[i].mem) {
			sgx_nr_epc_banks = i;
			ret = -ENOMEM;
			goto out_iounmap;
		}
#endif
		ret = sgx_page_cache_init(sgx_epc_banks[i].start,
			sgx_epc_banks[i].end - sgx_epc_banks[i].start);
		if (ret) {
			sgx_nr_epc_banks = i+1;
			goto out_iounmap;
		}
	}

	wq_flags = WQ_UNBOUND | WQ_FREEZABLE;
#ifdef WQ_NON_REENETRANT
	wq_flags |= WQ_NON_REENTRANT;
#endif
	sgx_add_page_wq = alloc_workqueue("intel_sgx-add-page-wq", wq_flags, 1);
	if (!sgx_add_page_wq) {
		pr_err("intel_sgx: alloc_workqueue() failed\n");
		ret = -ENOMEM;
		goto out_iounmap;
	}

	ret = misc_register(&sgx_dev);
	if (ret) {
		pr_err("intel_sgx: misc_register() failed\n");
		goto out_workqueue;
	}

	return 0;
out_workqueue:
	destroy_workqueue(sgx_add_page_wq);
out_iounmap:
#ifdef CONFIG_X86_64
	for (i = 0; i < sgx_nr_epc_banks; i++)
		iounmap(sgx_epc_banks[i].mem);
#endif
	return ret;
}

static __exit void sgx_exit(void)
{
	int i;

	misc_deregister(&sgx_dev);
	destroy_workqueue(sgx_add_page_wq);
#ifdef CONFIG_X86_64
	for (i = 0; i < sgx_nr_epc_banks; i++)
		iounmap(sgx_epc_banks[i].mem);
#endif
	sgx_page_cache_teardown();
}

module_init(sgx_init);
module_exit(sgx_exit);

MODULE_LICENSE("Dual BSD/GPL");
