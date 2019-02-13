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
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/ratelimit.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
	#include <linux/sched/signal.h>
#else
	#include <linux/signal.h>
#endif
#include <linux/slab.h>

#define SGX_NR_LOW_EPC_PAGES_DEFAULT 32
#define SGX_NR_SWAP_CLUSTER_MAX	16

static LIST_HEAD(sgx_free_list);
static LIST_HEAD(sgx_conflict_list);
static DEFINE_SPINLOCK(sgx_free_list_lock);
static int group_required;
LIST_HEAD(sgx_tgid_ctx_list);
DEFINE_MUTEX(sgx_tgid_ctx_mutex);
static unsigned int sgx_nr_total_epc_pages;
static unsigned int sgx_nr_free_pages;
static unsigned int sgx_nr_free_pages_conflict;
static unsigned int sgx_nr_low_pages = SGX_NR_LOW_EPC_PAGES_DEFAULT;
static unsigned int sgx_nr_high_pages;
struct task_struct *ksgxswapd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(ksgxswapd_waitq);

/* UCB */
static unsigned int conflict_group[MTAP_NUM_GROUP];
static unsigned int important_va_num_page = 0;
static unsigned int the_last_reserved_pa = 0;
static int sgx_test_and_clear_young_cb(pte_t *ptep, pgtable_t token,
				       unsigned long addr, void *data)
{
	pte_t pte;
	int ret;

	ret = pte_young(*ptep);
	if (ret) {
		pte = pte_mkold(*ptep);
		set_pte_at((struct mm_struct *)data, addr, ptep, pte);
	}

	return ret;
}

/**
 * sgx_test_and_clear_young() - Test and reset the accessed bit
 * @page:	enclave EPC page to be tested for recent access
 * @encl:	enclave which owns @page
 *
 * Checks the Access (A) bit from the PTE corresponding to the
 * enclave page and clears it.  Returns 1 if the page has been
 * recently accessed and 0 if not.
 */
int sgx_test_and_clear_young(struct sgx_encl_page *page, struct sgx_encl *encl)
{
	struct vm_area_struct *vma = sgx_find_vma(encl, page->addr);

	if (!vma)
		return 0;

	return apply_to_page_range(vma->vm_mm, page->addr, PAGE_SIZE,
				   sgx_test_and_clear_young_cb, vma->vm_mm);
}

static struct sgx_tgid_ctx *sgx_isolate_tgid_ctx(unsigned long nr_to_scan)
{
	struct sgx_tgid_ctx *ctx = NULL;
	int i;

	mutex_lock(&sgx_tgid_ctx_mutex);

	if (list_empty(&sgx_tgid_ctx_list)) {
		mutex_unlock(&sgx_tgid_ctx_mutex);
		return NULL;
	}

	for (i = 0; i < nr_to_scan; i++) {
		/* Peek TGID context from the head. */
		ctx = list_first_entry(&sgx_tgid_ctx_list,
				       struct sgx_tgid_ctx,
				       list);

		/* Move to the tail so that we do not encounter it in the
		 * next iteration.
		 */
		list_move_tail(&ctx->list, &sgx_tgid_ctx_list);

		/* Non-empty TGID context? */
		if (!list_empty(&ctx->encl_list) &&
		    kref_get_unless_zero(&ctx->refcount))
			break;

		ctx = NULL;
	}

	mutex_unlock(&sgx_tgid_ctx_mutex);

	return ctx;
}

static struct sgx_encl *sgx_isolate_encl(struct sgx_tgid_ctx *ctx,
					       unsigned long nr_to_scan)
{
	struct sgx_encl *encl = NULL;
	int i;

	mutex_lock(&sgx_tgid_ctx_mutex);

	if (list_empty(&ctx->encl_list)) {
		mutex_unlock(&sgx_tgid_ctx_mutex);
		return NULL;
	}

	for (i = 0; i < nr_to_scan; i++) {
		/* Peek encl from the head. */
		encl = list_first_entry(&ctx->encl_list, struct sgx_encl,
					encl_list);

		/* Move to the tail so that we do not encounter it in the
		 * next iteration.
		 */
		list_move_tail(&encl->encl_list, &ctx->encl_list);

		/* Enclave with faulted pages?  */
		if (!list_empty(&encl->load_list) &&
		    kref_get_unless_zero(&encl->refcount))
			break;

		encl = NULL;
	}

	mutex_unlock(&sgx_tgid_ctx_mutex);

	return encl;
}

static void sgx_isolate_pages(struct sgx_encl *encl,
			      struct list_head *dst,
			      unsigned long nr_to_scan)
{
	struct sgx_encl_page *entry;
	int i;

	mutex_lock(&encl->lock);

	if (encl->flags & SGX_ENCL_DEAD)
		goto out;

	for (i = 0; i < nr_to_scan; i++) {
		if (list_empty(&encl->load_list))
			break;

reselect_page:
    entry = list_first_entry(&encl->load_list,
        struct sgx_encl_page,
        load_list);

    if(entry->flags & SGX_ENCL_PAGE_PINNED)
    {
      list_move_tail(&entry->load_list, &encl->load_list);
      goto reselect_page;
    }

		if (!sgx_test_and_clear_young(entry, encl) &&
		    !(entry->flags & SGX_ENCL_PAGE_RESERVED)) {
			entry->flags |= SGX_ENCL_PAGE_RESERVED;
			list_move_tail(&entry->load_list, dst);
		} else {
			list_move_tail(&entry->load_list, &encl->load_list);
		}
	}
out:
	mutex_unlock(&encl->lock);
}

static void sgx_eblock(struct sgx_encl *encl,
		       struct sgx_epc_page *epc_page)
{
	void *vaddr;
	int ret;

	vaddr = sgx_get_page(epc_page);
	//ret = __eblock((unsigned long)vaddr);
	ret = 0;
	sgx_put_page(vaddr);

	if (ret) {
		sgx_crit(encl, "EBLOCK returned %d\n", ret);
		sgx_invalidate(encl, true);
	}

}

static void sgx_etrack(struct sgx_encl *encl)
{
	void *epc;
	int ret;

	epc = sgx_get_page(encl->secs_page.epc_page);
	//ret = __etrack(epc);
	ret = 0;
	sgx_put_page(epc);

	if (ret) {
		sgx_crit(encl, "ETRACK returned %d\n", ret);
		sgx_invalidate(encl, true);
	}
}

static int __sgx_ewb(struct sgx_encl *encl,
		     struct sgx_encl_page *encl_page)
{
	struct page *backing;
	void *backing_ptr;
	void *epc;
	int ret;

	backing = sgx_get_backing(encl, encl_page, false);
	if (IS_ERR(backing)) {
		ret = PTR_ERR(backing);
		sgx_warn(encl, "pinning the backing page for EWB failed with %d\n",
			 ret);
		return ret;
	}

	backing_ptr = kmap_atomic(backing);
	epc = sgx_get_page(encl_page->epc_page);
	memcpy(epc, backing, PAGE_SIZE);
	sgx_put_page(epc);
	kunmap_atomic(backing_ptr);
	sgx_put_backing(backing, true);
	return 0;
}

static bool sgx_ewb(struct sgx_encl *encl,
		    struct sgx_encl_page *entry)
{
	int ret = __sgx_ewb(encl, entry);

	if (ret == SGX_NOT_TRACKED) {
		/* slow path, IPI needed */
		sgx_flush_cpus(encl);
		ret = __sgx_ewb(encl, entry);
	}

	if (ret) {
		/* make enclave inaccessible */
		sgx_invalidate(encl, true);
		if (ret > 0)
			sgx_err(encl, "EWB returned %d, enclave killed\n", ret);
		return false;
	}

	return true;
}

static void sgx_evict_page(struct sgx_encl_page *entry,
			   struct sgx_encl *encl)
{
	sgx_ewb(encl, entry);
  sgx_free_page(entry->epc_page, encl);
	entry->epc_page = NULL;
	entry->flags &= ~SGX_ENCL_PAGE_RESERVED;
}

static void sgx_write_pages(struct sgx_encl *encl, struct list_head *src)
{
	struct sgx_encl_page *entry;
	struct sgx_encl_page *tmp;
	struct vm_area_struct *vma;

	if (list_empty(src))
		return;

	entry = list_first_entry(src, struct sgx_encl_page, load_list);

	mutex_lock(&encl->lock);

	/* EBLOCK */
	list_for_each_entry_safe(entry, tmp, src, load_list) {
		vma = sgx_find_vma(encl, entry->addr);
		if (vma) {
			zap_vma_ptes(vma, entry->addr, PAGE_SIZE);
		}

		sgx_eblock(encl, entry->epc_page);
	}

	/* ETRACK */
	sgx_etrack(encl);

	/* EWB */
	while (!list_empty(src)) {
		entry = list_first_entry(src, struct sgx_encl_page,
					 load_list);
		list_del(&entry->load_list);
		sgx_evict_page(entry, encl);
		encl->secs_child_cnt--;
	}

	if (!encl->secs_child_cnt && (encl->flags & SGX_ENCL_INITIALIZED)) {
		sgx_evict_page(&encl->secs_page, encl);
		encl->flags |= SGX_ENCL_SECS_EVICTED;
	}

	mutex_unlock(&encl->lock);
}

static void sgx_swap_pages(unsigned long nr_to_scan)
{
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	LIST_HEAD(cluster);

	ctx = sgx_isolate_tgid_ctx(nr_to_scan);
	if (!ctx)
		return;

	encl = sgx_isolate_encl(ctx, nr_to_scan);
	if (!encl)
		goto out;

	down_read(&encl->mm->mmap_sem);
	sgx_isolate_pages(encl, &cluster, nr_to_scan);
	sgx_write_pages(encl, &cluster);
	up_read(&encl->mm->mmap_sem);

	kref_put(&encl->refcount, sgx_encl_release);
out:
  kref_put(&ctx->refcount, sgx_tgid_ctx_release);
}

int ksgxswapd(void *p)
{
	while (!kthread_should_stop()) {
		wait_event_interruptible(ksgxswapd_waitq,
					 kthread_should_stop() ||
					 sgx_nr_free_pages < sgx_nr_high_pages);

		if (sgx_nr_free_pages < sgx_nr_high_pages)
			sgx_swap_pages(SGX_NR_SWAP_CLUSTER_MAX);
	}

	pr_info("%s: done\n", __func__);
	return 0;
}

int does_conflict(resource_size_t pa, int group_required)
{
  if( (GROUP( SET(pa) ) < group_required) && (GROUP( SET(pa) ) >= 0))
    return 1;
  else
    return 0;
}

int is_squeezing_reserved_pa(resource_size_t pa, int group_required)
{
  return (does_conflict(pa, group_required) && pa <= the_last_reserved_pa);
}

int init_conflict_group(resource_size_t start, unsigned long size)
{
  resource_size_t walk;
  int g;
  int cover = 0;
  important_va_num_page = MTAP_NUM_ADDITIONAL + (MTAP_PIN_VA_END - MTAP_PIN_VA_START)/PAGE_SIZE;
  pr_info("initializing conflict group..\n");
  // from the starting address, go through all the pages, 
  // and incr ement the counter for the group that the page belongs to.
  for(g=0; g<MTAP_NUM_GROUP; g++)
  {
    conflict_group[g] = 0;
  }
  for(walk = start; walk < start + size; walk += PAGE_SIZE)
  {
    int group;
    group = GROUP( SET(walk) );
    conflict_group[group] ++;
  }
  for(g=0; g<MTAP_NUM_GROUP; g++)
  {
    if(cover >= important_va_num_page)
      break;

    cover += conflict_group[g];
    group_required = g + 1;
  }

  pr_info("number of pages: %d, required number of groups %d\n", important_va_num_page, group_required);
  return 0;
}

int sgx_page_cache_init(resource_size_t start, unsigned long size)
{
	unsigned long i;
	struct sgx_epc_page *new_epc_page, *entry;
	struct list_head *parser, *temp;

	init_conflict_group(start, size);

	for (i = 0; i < size; i += PAGE_SIZE) {
		new_epc_page = kzalloc(sizeof(*new_epc_page), GFP_KERNEL);
		if (!new_epc_page)
			goto err_freelist;
		new_epc_page->pa = start + i;

		spin_lock(&sgx_free_list_lock);

    if(does_conflict(new_epc_page->pa, group_required) && the_last_reserved_pa == 0)
    {
      list_add_tail(&new_epc_page->free_list, &sgx_conflict_list);
      sgx_nr_free_pages_conflict++;
      if(sgx_nr_free_pages_conflict == important_va_num_page)
      {
        the_last_reserved_pa = new_epc_page->pa;
      }
    }
    else
    {
		  list_add_tail(&new_epc_page->free_list, &sgx_free_list);
		  sgx_nr_free_pages++;
    }
    sgx_nr_total_epc_pages++;
		
    spin_unlock(&sgx_free_list_lock);
	}

	sgx_nr_high_pages = 2 * sgx_nr_low_pages;
	ksgxswapd_tsk = kthread_run(ksgxswapd, NULL, "ksgxswapd");

	return 0;
err_freelist:
	list_for_each_safe(parser, temp, &sgx_free_list) {
		spin_lock(&sgx_free_list_lock);
		entry = list_entry(parser, struct sgx_epc_page, free_list);
		list_del(&entry->free_list);
		spin_unlock(&sgx_free_list_lock);
		kfree(entry);
	}
	return -ENOMEM;
}

void sgx_page_cache_teardown(void)
{
	struct sgx_epc_page *entry;
	struct list_head *parser, *temp;

	if (ksgxswapd_tsk)
		kthread_stop(ksgxswapd_tsk);

	spin_lock(&sgx_free_list_lock);
	list_for_each_safe(parser, temp, &sgx_free_list) {
		entry = list_entry(parser, struct sgx_epc_page, free_list);
		list_del(&entry->free_list);
		kfree(entry);
	}
	list_for_each_safe(parser, temp, &sgx_conflict_list) {
		entry = list_entry(parser, struct sgx_epc_page, free_list);
		list_del(&entry->free_list);
		kfree(entry);
	}
	spin_unlock(&sgx_free_list_lock);
}

static struct sgx_epc_page *sgx_alloc_conflict_fast(void)
{
  struct sgx_epc_page *entry = NULL;

  spin_lock(&sgx_free_list_lock);

  if(sgx_nr_free_pages_conflict == 0)
  {
    pr_info("fucked up\n");
  }

  if (!list_empty(&sgx_conflict_list)) {
    entry = list_first_entry(&sgx_conflict_list, struct sgx_epc_page, free_list);
    list_del(&entry->free_list);
    sgx_nr_free_pages_conflict--;
  }
  
  spin_unlock(&sgx_free_list_lock);
  
  return entry;
}

static struct sgx_epc_page *sgx_alloc_page_fast(void)
{
	struct sgx_epc_page *entry = NULL;

	spin_lock(&sgx_free_list_lock);

  if(sgx_nr_free_pages == 0)
  {
    pr_info("fucked up 2\n");
  }
	if (!list_empty(&sgx_free_list)) {
		entry = list_first_entry(&sgx_free_list, struct sgx_epc_page,
					 free_list);
		list_del(&entry->free_list);
		sgx_nr_free_pages--;
	}

	spin_unlock(&sgx_free_list_lock);

	return entry;
}

/**
 * sgx_alloc_page - allocate an EPC page
 * @flags:	allocation flags
 *
 * Try to grab a page from the free EPC page list. If there is a free page
 * available, it is returned to the caller. If called with SGX_ALLOC_ATOMIC,
 * the function will return immediately if the list is empty. Otherwise, it
 * will swap pages up until there is a free page available. Before returning
 * the low watermark is checked and ksgxswapd is waken up if we are below it.
 *
 * Return: an EPC page or a system error code
 */
struct sgx_epc_page *sgx_alloc_page(unsigned int flags)
{
	struct sgx_epc_page *entry;

	for ( ; ; ) {
    if(flags & SGX_ALLOC_CONFLICT) {
      entry = sgx_alloc_conflict_fast();
    }
    else {
      entry = sgx_alloc_page_fast();
    }
		if (entry)
			break;

		if (flags & SGX_ALLOC_ATOMIC) {
			entry = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current)) {
			entry = ERR_PTR(-ERESTARTSYS);
			break;
		}

		sgx_swap_pages(SGX_NR_SWAP_CLUSTER_MAX);
		schedule();
	}

	if (sgx_nr_free_pages < sgx_nr_low_pages)
		wake_up(&ksgxswapd_waitq);

	return entry;
}
EXPORT_SYMBOL(sgx_alloc_page);

/**
 * sgx_free_page - free an EPC page
 *
 * EREMOVE an EPC page and insert it back to the list of free pages. Optionally,
 * an enclave can be given as a parameter. If the enclave is given, the
 * resulting error is printed out loud as a critical error. It is an indicator
 * of a driver bug if that would happen.
 *
 * If the enclave is not given as a parameter (like in the case when VMM uses
 * this function)), it is fully up to the caller to deal with the return value,
 * including printing it to the klog if it wants to do such a thing.
 *
 * @entry:	an EPC page
 * @encl:	the enclave who owns the EPC page (optional)
 *
 * Return: SGX error code
 */
int sgx_free_page(struct sgx_epc_page *entry, struct sgx_encl *encl)
{
	void *epc;
	int ret;

	epc = sgx_get_page(entry);
	//ret = __eremove(epc);
	ret = 0;
	sgx_put_page(epc);

	if (ret) {
		if (encl)
			sgx_crit(encl, "EREMOVE returned %d\n", ret);

		return ret;
	}
	spin_lock(&sgx_free_list_lock);
  
  if(is_squeezing_reserved_pa(entry->pa, group_required)) {
    list_add(&entry->free_list, &sgx_conflict_list);
    sgx_nr_free_pages_conflict++;
  }
  else {
	  list_add(&entry->free_list, &sgx_free_list);
	  sgx_nr_free_pages++;
  }
	spin_unlock(&sgx_free_list_lock);

	return 0;
}
EXPORT_SYMBOL(sgx_free_page);

#define MTAP_CONFLICT_PAGES_ORDER  ((MTAP_NUM_SETS_ORDER + 6) - PAGE_SHIFT)
#define MTAP_CONFLICT_PAGES        (1ULL << MTAP_CONFLICT_PAGES_ORDER)

static struct page *conflict_pages[MTAP_CONFLICT_PAGES];

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
int sgx_conflict_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
#else
int sgx_conflict_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))
	unsigned long addr = (unsigned long) vmf->address;
#else
	unsigned long addr = (unsigned long) vmf->virtual_address;
#endif
	struct page *new = NULL, *new_pages;
	int ret, i, j;

	spin_lock(&sgx_free_list_lock);
	for (i = 0; i < MTAP_CONFLICT_PAGES; i++)
		if (conflict_pages[i]) {
			new = conflict_pages[i];
			conflict_pages[i] = NULL;
			break;
		}
	spin_unlock(&sgx_free_list_lock);
	if (new)
		goto done_alloc;

	new_pages = alloc_pages(GFP_KERNEL|__GFP_ZERO, MTAP_CONFLICT_PAGES_ORDER);
	if (!new_pages)
		return VM_FAULT_OOM;

	spin_lock(&sgx_free_list_lock);
	for (i = 0; i < MTAP_CONFLICT_PAGES; i++) {
		struct page *p = new_pages + i;
		u64 pa = page_to_pfn(p) << PAGE_SHIFT;
		if (!does_conflict(pa, group_required)) {
			__free_page(p);
			continue;
		}
		if (!new) {
			new = p;
			continue;
		}
		for (j = 0; j < MTAP_CONFLICT_PAGES; j++) {
			if (!conflict_pages[j]) {
				conflict_pages[j] = p;
				p = NULL;
				break;
			}
		}
		if (p) {
			__free_page(p);
			continue;
		}
	}
	spin_unlock(&sgx_free_list_lock);

done_alloc:
	BUG_ON(!new);
	ret = vm_insert_pfn(vma, addr, page_to_pfn(new));
	if (ret < 0) {
		__free_page(new);
	} else {
		vmf->page = new;
	}
	return ret;
}

void *sgx_get_page(struct sgx_epc_page *entry)
{
#ifdef CONFIG_X86_32
	return kmap_atomic_pfn(PFN_DOWN(entry->pa));
#else
	int i;

	for (i = 0; i < sgx_nr_epc_banks; i++) {
		if (entry->pa < sgx_epc_banks[i].end &&
		    entry->pa >= sgx_epc_banks[i].start) {
			return sgx_epc_banks[i].mem +
				(entry->pa - sgx_epc_banks[i].start);
		}
	}

	return NULL;
#endif
}
EXPORT_SYMBOL(sgx_get_page);

void sgx_put_page(void *epc_page_vaddr)
{
#ifdef CONFIG_X86_32
	kunmap_atomic(epc_page_vaddr);
#else
#endif
}
EXPORT_SYMBOL(sgx_put_page);
