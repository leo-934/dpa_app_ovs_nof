/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/* Source file for device part of packet processing sample.
 * Contain functions for initialize contexts of internal queues,
 * read, check, change and resend the packet and wait for another.
 */

/* Shared header file with utilities for samples.
 * The file also have includes to flexio_dev_ver.h and flexio_dev.h
 * The include must be placed first to correctly handle the version.
 */
#include "com_dev.h"
#include <libflexio-dev/flexio_dev_err.h>
#include <libflexio-dev/flexio_dev_queue_access.h>
#include <libflexio-dev/flexio_dev_debug.h>
#include <libflexio-libc/string.h>
#include <stddef.h>
#include <dpaintrin.h>
/* Shared header file for packet processor sample */
#include "../flexio_packet_processor_com.h"

/* Mask for CQ index */
#define CQ_IDX_MASK ((1 << LOG_CQ_DEPTH) - 1)
/* Mask for RQ index */
#define RQ_IDX_MASK ((1 << LOG_RQ_DEPTH) - 1)
/* Mask for SQ index */
#define SQ_IDX_MASK ((1 << (LOG_SQ_DEPTH + LOG_SQE_NUM_SEGS)) - 1)
/* Mask for data index */
#define DATA_IDX_MASK ((1 << (LOG_SQ_DEPTH)) - 1)

#define ACK_MSG_SIZE 64

#define ETH_HEADER_SIZE 42

/* The structure of the sample DPA application contains global data that the application uses */
static struct dpa_thread_context {
	/* Packet count - used for debug message */
	uint64_t packets_count;
	/* lkey - local memory key */
	uint32_t sq_lkey;
	uint32_t rq_lkey;
	int buffer_location;
	uint32_t window_id;
	flexio_uintptr_t nvme_queue;
	uint64_t nvme_packet_idx;

	cq_ctx_t rq_cq_ctx;     /* RQ CQ */
	rq_ctx_t rq_ctx;        /* RQ */
	sq_ctx_t sq_ctx;        /* SQ */
	cq_ctx_t sq_cq_ctx;     /* SQ CQ */
	dt_ctx_t dt_ctx;        /* SQ Data ring */
} thd_ctx[190];

/* Initialize the app_ctx structure from the host data.
 *  data_from_host - pointer host2dev_packet_processor_data from host.
 */
static void thd_ctx_init(struct host2dev_packet_processor_data *data_from_host)
{
	int i = data_from_host->thd_id;
	thd_ctx[i].packets_count = 0;
	thd_ctx[i].sq_lkey = data_from_host->sq_transf.wqd_mkey_id;
	thd_ctx[i].rq_lkey = data_from_host->rq_transf.wqd_mkey_id;
	thd_ctx[i].buffer_location = data_from_host->buffer_location;
	thd_ctx[i].window_id = data_from_host->window_id;
	thd_ctx[i].nvme_packet_idx = 0;

	/* Set context for RQ's CQ */
	com_cq_ctx_init(&(thd_ctx[i].rq_cq_ctx),
			data_from_host->rq_cq_transf.cq_num,
			data_from_host->rq_cq_transf.log_cq_depth,
			data_from_host->rq_cq_transf.cq_ring_daddr,
			data_from_host->rq_cq_transf.cq_dbr_daddr);

	/* Set context for RQ */
	com_rq_ctx_init(&(thd_ctx[i].rq_ctx),
			data_from_host->rq_transf.wq_num,
			data_from_host->rq_transf.wq_ring_daddr,
			data_from_host->rq_transf.wq_dbr_daddr);

	/* Set context for SQ */
	com_sq_ctx_init(&(thd_ctx[i].sq_ctx),
			data_from_host->sq_transf.wq_num,
			data_from_host->sq_transf.wq_ring_daddr);

	/* Set context for SQ's CQ */
	com_cq_ctx_init(&(thd_ctx[i].sq_cq_ctx),
			data_from_host->sq_cq_transf.cq_num,
			data_from_host->sq_cq_transf.log_cq_depth,
			data_from_host->sq_cq_transf.cq_ring_daddr,
			data_from_host->sq_cq_transf.cq_dbr_daddr);

	/* Set context for data */
	com_dt_ctx_init(&(thd_ctx[i].dt_ctx), data_from_host->sq_transf.wqd_daddr);


	for (int a = 0; a < (1UL << LOG_SQ_DEPTH); a++) {

		union flexio_dev_sqe_seg *swqe;
        swqe = get_next_sqe(&(thd_ctx[i].sq_ctx), SQ_IDX_MASK);
		flexio_dev_swqe_seg_ctrl_set(swqe, a, thd_ctx[i].sq_ctx.sq_number,
				     MLX5_CTRL_SEG_CE_CQE_ON_CQE_ERROR, FLEXIO_CTRL_SEG_SEND_EN);

		swqe = get_next_sqe(&(thd_ctx[i].sq_ctx), SQ_IDX_MASK);
		flexio_dev_swqe_seg_eth_set(swqe, 0, 0, 0, NULL);

        swqe = get_next_sqe(&(thd_ctx[i].sq_ctx), SQ_IDX_MASK);
		flexio_dev_swqe_seg_mem_ptr_data_set(swqe, 0, thd_ctx->sq_lkey, 0);

        swqe = get_next_sqe(&(thd_ctx[i].sq_ctx), SQ_IDX_MASK);
	}
    thd_ctx[i].sq_ctx.sq_wqe_seg_idx = 0;
}

static void process_packet(struct flexio_dev_thread_ctx *dtctx, struct dpa_thread_context* thd_ctx, int use_copy)
{
	/* RX packet handling variables */
	struct flexio_dev_wqe_rcv_data_seg *rwqe;
	/* RQ WQE index */
	uint32_t rq_wqe_idx;
	/* Pointer to RQ data */
	char *rq_data;

	/* TX packet handling variables */
	union flexio_dev_sqe_seg *swqe;
	/* Pointer to SQ data */
	char *sq_data;

	/* Size of the data */
	uint32_t data_sz;
	uint32_t pkt_type;

	/* Extract relevant data from the CQE */
	rq_wqe_idx = flexio_dev_cqe_get_wqe_counter(thd_ctx->rq_cq_ctx.cqe);
	data_sz = flexio_dev_cqe_get_byte_cnt(thd_ctx->rq_cq_ctx.cqe);

	/* Get the RQ WQE pointed to by the CQE */
	rwqe = &(thd_ctx->rq_ctx.rq_ring[rq_wqe_idx & RQ_IDX_MASK]);

	/* Extract data (whole packet) pointed to by the RQ WQE */
	rq_data = flexio_dev_rwqe_get_addr(rwqe);


	pkt_type = *((uint32_t*)(rq_data + 42) + 1);
	if (pkt_type == 0) {
		if (use_copy == 0) {
			sq_data = rq_data;
		}
		else {
			/* Take the next entry from the data ring */
			sq_data = get_next_dte(&(thd_ctx->dt_ctx), DATA_IDX_MASK, LOG_WQD_CHUNK_BSIZE);	
			/* Copy received packet to sq_data as is */
			memcpy(sq_data, rq_data, data_sz);
		}
	
		/* swap mac address */
		swap_macs(sq_data);
	
		swqe = &(thd_ctx->sq_ctx.sq_ring[(thd_ctx->sq_ctx.sq_wqe_seg_idx + 2) & SQ_IDX_MASK]);
		thd_ctx->sq_ctx.sq_wqe_seg_idx += 4;
		flexio_dev_swqe_seg_mem_ptr_data_set(swqe, data_sz, thd_ctx->sq_lkey, (uint64_t)sq_data);
	}
	else {
		data_sz -= ETH_HEADER_SIZE;
		memcpy((void*)(thd_ctx->nvme_queue + (thd_ctx->nvme_packet_idx % NVME_QUEUE_ENTRY_NUM) * NVME_QUEUE_ENTRY_SIZE), rq_data + ETH_HEADER_SIZE, data_sz > NVME_QUEUE_ENTRY_SIZE ? NVME_QUEUE_ENTRY_SIZE : data_sz);
		
		// memcpy((void*)(thd_ctx->nvme_queue + (thd_ctx->nvme_packet_idx % NVME_QUEUE_ENTRY_NUM) * NVME_QUEUE_ENTRY_SIZE), rq_data, NVME_QUEUE_ENTRY_SIZE);
		thd_ctx->nvme_packet_idx++;
	
		__dpa_thread_window_writeback();
	
		swqe = &(thd_ctx->sq_ctx.sq_ring[(thd_ctx->sq_ctx.sq_wqe_seg_idx + 2) & SQ_IDX_MASK]);
		thd_ctx->sq_ctx.sq_wqe_seg_idx += 4;
		flexio_dev_swqe_seg_mem_ptr_data_set(swqe, ACK_MSG_SIZE, thd_ctx->sq_lkey, (uint64_t)rq_data);
	}

	/* Ring DB */
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_qp_sq_ring_db(++thd_ctx->sq_ctx.sq_pi, thd_ctx->sq_ctx.sq_number);
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_dbr_rq_inc_pi(thd_ctx->rq_ctx.rq_dbr);
}

inline static char* get_dpa_host_rq_data_addr(char* host_addr, struct dpa_thread_context* thd_ctx) {
	return (char*)((flexio_uintptr_t)host_addr - (thd_ctx->rq_ctx.rqd_host_addr) + (thd_ctx->rq_ctx.rqd_dpa_addr));
}

inline static char* get_dpa_host_sq_data_addr(char* host_addr, struct dpa_thread_context* thd_ctx) {
	return (char*)((flexio_uintptr_t)host_addr - (thd_ctx->sq_ctx.sqd_host_addr) + (thd_ctx->sq_ctx.sqd_dpa_addr));
}

static void process_packet_host(struct flexio_dev_thread_ctx *dtctx, struct dpa_thread_context* thd_ctx, int use_copy)
{
	/* RX packet handling variables */
	struct flexio_dev_wqe_rcv_data_seg *rwqe;
	/* RQ WQE index */
	uint32_t rq_wqe_idx;
	/* Pointer to RQ data */
	char *rq_data_host, *rq_data_dpa;

	/* TX packet handling variables */
	union flexio_dev_sqe_seg *swqe;
	/* Pointer to SQ data */
	char *sq_data_host, *sq_data_dpa;

	/* Size of the data */
	uint32_t data_sz;
	uint32_t pkt_type;

	/* Extract relevant data from the CQE */
	rq_wqe_idx = flexio_dev_cqe_get_wqe_counter(thd_ctx->rq_cq_ctx.cqe);
	data_sz = flexio_dev_cqe_get_byte_cnt(thd_ctx->rq_cq_ctx.cqe);

	/* Get the RQ WQE pointed to by the CQE */
	rwqe = &(thd_ctx->rq_ctx.rq_ring[rq_wqe_idx & RQ_IDX_MASK]);

	/* Extract data (whole packet) pointed to by the RQ WQE */
	rq_data_host = flexio_dev_rwqe_get_addr(rwqe);
	rq_data_dpa = get_dpa_host_rq_data_addr(rq_data_host, thd_ctx);

	pkt_type = *((uint32_t*)(rq_data_dpa + 42) + 1);
	if (pkt_type == 0) {
		if (use_copy == 0) {
			sq_data_host = rq_data_host;
			sq_data_dpa = rq_data_dpa;
		}
		else {
			sq_data_host = get_next_dte(&(thd_ctx->dt_ctx), DATA_IDX_MASK, LOG_WQD_CHUNK_BSIZE);
			sq_data_dpa = get_dpa_host_sq_data_addr(sq_data_host, thd_ctx);
			memcpy(sq_data_dpa, rq_data_dpa, data_sz);
		}
	
		/* swap mac address */
		swap_macs(sq_data_dpa);
	
		__dpa_thread_window_writeback();
	
		swqe = &(thd_ctx->sq_ctx.sq_ring[(thd_ctx->sq_ctx.sq_wqe_seg_idx + 2) & SQ_IDX_MASK]);
		thd_ctx->sq_ctx.sq_wqe_seg_idx += 4;
		flexio_dev_swqe_seg_mem_ptr_data_set(swqe, data_sz, thd_ctx->sq_lkey, (uint64_t)sq_data_host);
	}
	else {
		data_sz -= ETH_HEADER_SIZE;
		memcpy((void*)(thd_ctx->nvme_queue + (thd_ctx->nvme_packet_idx % NVME_QUEUE_ENTRY_NUM) * NVME_QUEUE_ENTRY_SIZE), rq_data_dpa + ETH_HEADER_SIZE, data_sz > NVME_QUEUE_ENTRY_SIZE ? NVME_QUEUE_ENTRY_SIZE : data_sz);
		// memcpy((void*)(thd_ctx->nvme_queue + (thd_ctx->nvme_packet_idx % NVME_QUEUE_ENTRY_NUM) * NVME_QUEUE_ENTRY_SIZE), rq_data_dpa, NVME_QUEUE_ENTRY_SIZE);
		thd_ctx->nvme_packet_idx++;

		__dpa_thread_window_writeback();

		swqe = &(thd_ctx->sq_ctx.sq_ring[(thd_ctx->sq_ctx.sq_wqe_seg_idx + 2) & SQ_IDX_MASK]);
		thd_ctx->sq_ctx.sq_wqe_seg_idx += 4;
		flexio_dev_swqe_seg_mem_ptr_data_set(swqe, ACK_MSG_SIZE, thd_ctx->sq_lkey, (uint64_t)rq_data_host);
	}

	/* Ring DB */
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_qp_sq_ring_db(++thd_ctx->sq_ctx.sq_pi, thd_ctx->sq_ctx.sq_number);
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_dbr_rq_inc_pi(thd_ctx->rq_ctx.rq_dbr);

}

#define test_size_in_bytes 102400000
#define test_packet_count 100000

flexio_dev_event_handler_t flexio_pp_dev;
__dpa_global__ void flexio_pp_dev(uint64_t thread_arg)
{
	struct host2dev_packet_processor_data *data_from_host = (void *)thread_arg;
	struct flexio_dev_thread_ctx *dtctx;
	int i = data_from_host->thd_id;
	register int buffer_location = data_from_host->buffer_location;
	register int use_copy = data_from_host->use_copy;
	flexio_uintptr_t result = 0;

	flexio_dev_get_thread_ctx(&dtctx);
	flexio_dev_print("start thread %d %d\n", i, buffer_location);

	if (!data_from_host->not_first_run) {
		thd_ctx_init(data_from_host);
		if (buffer_location == 0) {
			thd_ctx[i].rq_ctx.rqd_dpa_addr = data_from_host->rq_transf.wqd_daddr;
			thd_ctx[i].sq_ctx.sqd_dpa_addr = data_from_host->sq_transf.wqd_daddr;
			flexio_dev_status_t ret;
			ret = flexio_dev_window_config(FLEXIO_DEV_WINDOW_ENTITY_0, (uint16_t)thd_ctx[i].window_id, data_from_host->result_buffer_mkey_id);
			if (ret != FLEXIO_DEV_STATUS_SUCCESS) {
				flexio_dev_print("failed to config rq window, thread %d\n", i);
			}
			ret = flexio_dev_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_0, (uint64_t)(data_from_host->result_buffer), &(result));
			if (ret != FLEXIO_DEV_STATUS_SUCCESS) {
				flexio_dev_print("failed to acquire result ptr, thread %d\n", i);
				// while(1);
			}
			ret = flexio_dev_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_0, (uint64_t)(data_from_host->nvme_queue), &(thd_ctx[i].nvme_queue));
			if (ret != FLEXIO_DEV_STATUS_SUCCESS) {
				flexio_dev_print("failed to acquire result ptr, thread %d\n", i);
			}
		}
		else {
			thd_ctx[i].rq_ctx.rqd_host_addr = data_from_host->rq_transf.wqd_daddr;
			thd_ctx[i].sq_ctx.sqd_host_addr = data_from_host->sq_transf.wqd_daddr;
			flexio_dev_status_t ret;
			ret = flexio_dev_window_config(FLEXIO_DEV_WINDOW_ENTITY_0, (uint16_t)thd_ctx[i].window_id, thd_ctx[i].rq_lkey);
			if (ret != FLEXIO_DEV_STATUS_SUCCESS) {
				flexio_dev_print("failed to config rq window, thread %d\n", i);
			}
			ret = flexio_dev_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_0, (uint64_t)data_from_host->rq_transf.wqd_daddr, &(thd_ctx[i].rq_ctx.rqd_dpa_addr));
			if (ret != FLEXIO_DEV_STATUS_SUCCESS) {
				flexio_dev_print("failed to acquire rq host ptr, thread %d\n", i);
			}
			// ret = flexio_dev_window_config((uint16_t)thd_ctx[i].window_id, thd_ctx[i].sq_lkey);
			// if (ret != FLEXIO_DEV_STATUS_SUCCESS) {
			// 	flexio_dev_print("failed to config sq window, thread %d\n", i);
			// }
			ret = flexio_dev_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_0, (uint64_t)data_from_host->sq_transf.wqd_daddr, &(thd_ctx[i].sq_ctx.sqd_dpa_addr));
			if (ret != FLEXIO_DEV_STATUS_SUCCESS) {
				flexio_dev_print("failed to acquire sq host ptr, thread %d\n", i);
			}		
			// flexio_dev_print("before host addr: 0x%llx, dpa addr: 0x%llx\n", data_from_host->result_buffer, result);	
			ret = flexio_dev_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_0, (uint64_t)(data_from_host->result_buffer), &(result));
			if (ret != FLEXIO_DEV_STATUS_SUCCESS) {
				flexio_dev_print("failed to acquire result ptr, thread %d\n", i);
				// while(1);
			}
			ret = flexio_dev_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_0, (uint64_t)(data_from_host->nvme_queue), &(thd_ctx[i].nvme_queue));
			if (ret != FLEXIO_DEV_STATUS_SUCCESS) {
				flexio_dev_print("failed to acquire result ptr, thread %d\n", i);
			}
			// flexio_dev_print("after host addr: 0x%llx, dpa addr: 0x%llx\n", data_from_host->result_buffer, result);	
		}
		data_from_host->not_first_run = 1;
		// struct host_to_device_config *device_cfg = (struct host_to_device_config *)data_from_host->device_cfg_p;
		// result = flexio_dev_window_config(FLEXIO_DEV_WINDOW_ENTITY_0, device_cfg->window_id, device_cfg->mkey);
		// if (result != FLEXIO_DEV_STATUS_SUCCESS) {
		// 	flexio_dev_print("flexio_dev_window_config failed\n");
		// 	return;
		// }
		// flexio_uintptr_t a;
		// result = flexio_dev_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_0, device_cfg->haddr, &a);
		// if (result != FLEXIO_DEV_STATUS_SUCCESS) {
		// 	flexio_dev_print("flexio_dev_window_ptr_acquire failed\n");
		// 	return;
		// }
		// __dpa_thread_memory_writeback();
	}

	register size_t pkt_count = 0;
	register size_t start = __dpa_thread_cycles();
	register size_t end;
    // register size_t trigger_time = 0;
    // register size_t time_total = __dpa_thread_cycles();
	while (dtctx != NULL) {
		while (flexio_dev_cqe_get_owner(thd_ctx[i].rq_cq_ctx.cqe) != thd_ctx[i].rq_cq_ctx.cq_hw_owner_bit) {
			__dpa_thread_fence(__DPA_MEMORY, __DPA_R, __DPA_R);
			if (buffer_location == 0) {
				process_packet(dtctx, &thd_ctx[i], use_copy);
			}
			else {
				process_packet_host(dtctx, &thd_ctx[i], use_copy);
			}
			com_step_cq(&(thd_ctx[i].rq_cq_ctx));
			// pkt_count++;
			// if (__builtin_expect((pkt_count == test_packet_count), 0)) {
			// 	// trigger_time++;
			// 	// if (i == 0) {
			// 	end = __dpa_thread_cycles();
			// 	uint64_t speed = 1024ULL * 8 * (pkt_count * 1024) / (( end - start) * 10 / 18);
			// 	// flexio_dev_print("result buffer: 0x%llx\n", result);
			// 	// flexio_dev_print("thread_id: %d, speed: %llu Mbps\n", i, speed);
			// 	// uint64_t test;
			// 	// memcpy(&test,(void*)result, sizeof(uint64_t));
			// 	// flexio_dev_print("before host addr: 0x%lx, result: %lu, speed: %lu\n", data_from_host->result_buffer, test, speed);
			// 	// flexio_dev_print("before host addr: 0x%llu, result: %lu, speed: %lu\n", data_from_host->result_buffer, *((uint64_t*)result), speed);
			// 	*((uint64_t*)result) = speed;
			// 	__dpa_thread_window_writeback();
			// 	// memcpy(&test,(void*)result, sizeof(uint64_t));
			// 	// flexio_dev_print("after host addr: 0x%lx, result: %lu, speed: %lu\n", data_from_host->result_buffer, *((uint64_t*)result), speed);
			// 	// flexio_dev_print("after host addr: 0x%llu, result: %lu, speed: %lu\n", data_from_host->result_buffer, *((uint64_t*)result), speed);
			// 	// flexio_dev_print("result speed: %llu Mbps\n", *((uint64_t*)result));
			// 	// }
			// 	// struct host_to_device_config *device_cfg = (struct host_to_device_config *)data_from_host->device_cfg_p;
			// 	// result = flexio_dev_window_config(dtctx, device_cfg->window_id, device_cfg->mkey);
			// 	// if (result != FLEXIO_DEV_STATUS_SUCCESS) {
			// 	// 	flexio_dev_print("flexio_dev_window_config failed\n");
			// 	// 	return;
			// 	// }
			// 	// result = flexio_dev_window_ptr_acquire(dtctx, device_cfg->haddr, &a);
			// 	// if (result != FLEXIO_DEV_STATUS_SUCCESS) {
			// 	// 	flexio_dev_print("flexio_dev_window_ptr_acquire failed\n");
			// 	// 	return;
			// 	// }
			// 	// *((uint64_t*)a) = 1024ULL * 8 * (data_from_host->recv_sz) / used_time;
			// 	start = __dpa_thread_cycles();
			// 	pkt_count = 0;

            //     // if (trigger_time > 3) {
            //     //     flexio_dev_print("thread %ld end due to trigger-time limit\n", i);
            //     //     return;
            //     // }
            // }
            // if (__dpa_thread_cycles() - time_total > 1800ULL * 1000 * 1000 * 30) {
            //     flexio_dev_print("thread %ld end due to time limit\n", i);
            //     return;
            // }
		}
	}

	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_cq_arm(thd_ctx[i].rq_cq_ctx.cq_idx, thd_ctx[i].rq_cq_ctx.cq_number);
	flexio_dev_thread_reschedule();
}
