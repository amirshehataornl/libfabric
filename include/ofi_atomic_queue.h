/*
 * Copyright (c) 2022 UT-Battelle ORNL. All rights reserved
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

#ifndef OFI_ATOMIC_QUEUE_H
#define OFI_ATOMIC_QUEUE_H

#include <ofi_atom.h>

/*
 * This is an atomic queue, meaning no need for locking. One example usage
 * for this data structure is to build a command queue shared between
 * different processes. Multiple processes would post commands on a command
 * queue which belongs to another process. The receiving process would
 * read and process commands off the queue.
 *
 * Usage:
 *  . OFI_DECLARE_ATOMIQ() to declare the atomic queue
 *  . Allocate shared memory for the queue or call the create method
 *  . call the init() method to ready the queue for usage
 *  . To post on the queue call tx_next() method
 *     . This will return a buffer of entrytype
 *     . Initialize the entry
 *  . Call tx_advance() method to post for the reader
 *  . To read off the queue call rx_next()
 *     . This will return the next available entry on the queue or
 *       -FI_ENOENT if there are no more entries on the queue
 *  . Call the rx_adance() after you've completed using the entry
 */

#ifdef __cplusplus
extern "C" {
#endif

#define OFI_CACHE_LINE_SIZE (64)

#define OFI_DECLARE_ATOMIQ(entrytype, name)			\
struct name ## _entry {						\
	ofi_atomic64_t	seq;					\
	entrytype	buf;					\
};								\
struct name {							\
	int		size;					\
	int		size_mask;				\
	ofi_atomic64_t	enqueue_pos;				\
	char		pad0[OFI_CACHE_LINE_SIZE];		\
	ofi_atomic64_t	dequeue_pos;				\
	char		pad1[OFI_CACHE_LINE_SIZE];		\
	struct name ## _entry entry[];				\
} __attribute__((__aligned__(64)));				\
								\
static inline void name ## _init(struct name *aq, size_t size)	\
{								\
	size_t i;						\
	assert(size == roundup_power_of_two(size));		\
	aq->size = size;					\
	aq->size_mask = aq->size - 1;				\
	ofi_atomic_initialize64(&aq->enqueue_pos, 0);		\
	ofi_atomic_initialize64(&aq->dequeue_pos, 0);		\
	for (i = 0; i < size; i++)				\
		ofi_atomic_initialize64(&aq->entry[i].seq, i);	\
}								\
								\
static inline struct name * name ## _create(size_t size)	\
{								\
	struct name *aq;					\
	aq = (struct name*) calloc(1, sizeof(*aq) +		\
		sizeof(struct name ## _entry) *			\
		(roundup_power_of_two(size)));			\
	if (aq)							\
		name ##_init(aq, roundup_power_of_two(size));	\
	return aq;						\
}								\
								\
static inline void name ## _free(struct name *aq)		\
{								\
	free(aq);						\
}								\
static inline int name ## _tx_next(struct name *aq,		\
		entrytype **buf, size_t *pos)			\
{								\
	struct name ## _entry *e;				\
	size_t diff, seq;					\
	*pos = atomic_load_explicit(&aq->enqueue_pos.val,	\
				    memory_order_relaxed);	\
	for (;;) {						\
		e = &aq->entry[*pos & aq->size_mask];		\
		seq = atomic_load_explicit(&(e->seq.val),	\
			memory_order_acquire);			\
		diff = seq - *pos;				\
		if (diff == 0) {				\
			if(atomic_compare_exchange_weak(	\
				&aq->enqueue_pos.val, pos,	\
				*pos + 1))			\
				break;				\
		} else if (diff < 0) {				\
			return -FI_EAGAIN;			\
		} else {					\
			*pos = atomic_load_explicit(		\
				&aq->enqueue_pos.val,		\
				memory_order_relaxed);		\
		}						\
	}							\
	*buf = &e->buf;						\
	return FI_SUCCESS;					\
}								\
static inline int name ## _rx_next(struct name *aq,		\
		entrytype **buf, size_t *pos)			\
{								\
	size_t diff, seq;					\
	struct name ## _entry *e;				\
	*pos = atomic_load_explicit(&aq->dequeue_pos.val,	\
			memory_order_relaxed);			\
	for (;;) {						\
		e = &aq->entry[*pos & aq->size_mask];		\
		seq = e->seq.val;				\
		diff = seq - (*pos + 1);			\
		if (diff == 0) {				\
			if(atomic_compare_exchange_weak(	\
				&aq->dequeue_pos.val, pos,	\
				*pos + 1))			\
				break;				\
		} else if (diff < 0) {				\
			return -FI_ENOENT;			\
		} else {					\
			*pos = atomic_load_explicit(		\
				&aq->dequeue_pos.val,		\
				memory_order_relaxed);		\
		}						\
	}							\
	*buf = &e->buf;						\
	return FI_SUCCESS;					\
}								\
static inline void name ## _tx_advance(entrytype *buf,		\
				size_t pos)			\
{								\
	struct name ## _entry *e;				\
	e = container_of(buf, struct name ## _entry, buf);	\
	atomic_store_explicit(&e->seq.val, pos + 1,		\
			      memory_order_release);		\
}								\
static inline void name ## _rx_advance (struct name *aq,	\
			entrytype *buf,				\
			size_t pos)				\
{								\
	struct name ## _entry *e;				\
	e = container_of(buf, struct name ## _entry, buf);	\
	atomic_store_explicit(&e->seq.val, pos + aq->size_mask,	\
			      memory_order_release);		\
}								\
void dummy ## name (void) /* work-around global ; scope */

#ifdef __cplusplus
}
#endif

#endif /* OFI_ATOMIC_QUEUE_H */
