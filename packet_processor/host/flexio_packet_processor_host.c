/* Used for geteuid function. */
#include <unistd.h>

/* Used for host (x86/DPU) memory allocations. */
#include <malloc.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <inttypes.h>
#include <assert.h>

/* Used for IBV device operations. */
#include <infiniband/mlx5dv.h>

/* Flex IO SDK host side version API header. */
// #include <libflexio/flexio_ver.h>

/* Flex IO SDK host side API header. */
#include <libflexio/flexio.h>

/* Flow steering utilities helper header. */
#include "com_host.h"

/* Common header for communication between host and DPA. */
#include "../flexio_packet_processor_com.h"

/* Flex IO packet processor application struct.
 * Created by DPACC during compilation. The DEV_APP_NAME
 * is a macro transferred from Meson through gcc, with the
 * same name as the created application.
 */
extern struct flexio_app *DEV_APP_NAME;
/* Flex IO packet processor device (DPA) side function stub. */
extern flexio_func_t flexio_pp_dev;

/* Application context struct holding necessary host side variables */
struct app_context {
	struct flexio_process *flexio_process;
	struct flexio_window *flexio_window;
	struct flexio_msg_stream *stream;
	struct flexio_msg_stream **streams;
	struct flexio_uar *process_uar;
	struct ibv_pd *process_pd;
	struct ibv_context *ibv_ctx;
	struct ibv_mr *mr;

	void* result_buff;

	/* RX flow matcher. */
	struct flow_matcher *rx_matcher;
	/* TX flow matcher. */
	struct flow_matcher *tx_matcher;

};

struct thread_context {
	struct flexio_event_handler *event_handler;
	/* Flex IO SQ's CQ. */
	struct flexio_cq *flexio_sq_cq_ptr;
	/* Flex IO SQ. */
	struct flexio_sq *flexio_sq_ptr;
	/* Flex IO RQ's CQ. */
	struct flexio_cq *flexio_rq_cq_ptr;
	/* Flex IO RQ. */
	struct flexio_rq *flexio_rq_ptr;
	/* Transfer structs with information to pass to DPA side.
	 * The structs are defined by a common header which both sides may use.
	 */
	/* SQ's CQ transfer information. */
	struct app_transfer_cq sq_cq_transf;
	/* SQ transfer information. */
	struct app_transfer_wq sq_transf;
	/* RQ's CQ transfer information. */
	struct app_transfer_cq rq_cq_transf;
	/* RQ transfer information. */
	struct app_transfer_wq rq_transf;

	/* Memory key (MKey) for SQ data. */
	struct flexio_mkey *sqd_mkey;
	/* MKey for RQ data. */
	struct flexio_mkey *rqd_mkey;
	struct ibv_mr* mr;

	flexio_uintptr_t app_data_daddr;

	struct mlx5dv_devx_obj *rq_tir_obj;
	struct mlx5dv_dr_action* rq_action;
	struct mlx5dv_dr_rule* rx_dr_rule;

	struct mlx5dv_dr_action* tx_action;
	struct mlx5dv_dr_rule* tx_dr_rule;
	struct mlx5dv_dr_action* tx_action2;
	struct mlx5dv_dr_rule* tx_dr_rule2;

	uint32_t result_buffer_mkey_id;
	void* result_buffer;


	int thd_id;
};

/* Open ibv device
 * Returns 0 on success and -1 if the destroy was failed.
 * app_ctx - app_ctx - pointer to app_context structure.
 * device - device name to open.
 */
static int app_open_ibv_ctx(struct app_context *app_ctx, char *device)
{
	/* Queried IBV device list. */
	struct ibv_device **dev_list;
	/* Fucntion return value. */
	int ret = 0;
	/* IBV device iterator. */
	int dev_i;

	/* Query IBV devices list. */
	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		printf("Failed to get IB devices list\n");
		return -1;
	}

	/* Loop over found IBV devices. */
	for (dev_i = 0; dev_list[dev_i]; dev_i++) {
		/* Look for a device with the user provided name. */
		if (!strcmp(ibv_get_device_name(dev_list[dev_i]), device))
			break;
	}

	/* Check a device was found. */
	if (!dev_list[dev_i]) {
		printf("No IBV device found for device name '%s'\n", device);
		ret = -1;
		goto cleanup;
	}

	/* Open IBV device context for the requested device. */
	app_ctx->ibv_ctx = ibv_open_device(dev_list[dev_i]);
	if (!app_ctx->ibv_ctx) {
		printf("Couldn't open an IBV context for device '%s'\n", device);
		ret = -1;
	}

cleanup:
	/* Free queried IBV devices list. */
	ibv_free_device_list(dev_list);

	return ret;
}

/* Convert logarithm to value */
#define L2V(l) (1UL << (l))
/* Number of entries in each RQ/SQ/CQ is 2^LOG_Q_DEPTH. */
#define LOG_Q_DEPTH 7
#define Q_DEPTH L2V(LOG_Q_DEPTH)
/* SQ/RQ data entry byte size is 2048B (enough for ethernet packet data). */
#define LOG_Q_DATA_ENTRY_BSIZE 13
/* SQ/RQ data entry byte size log to value. */
#define Q_DATA_ENTRY_BSIZE L2V(LOG_Q_DATA_ENTRY_BSIZE)
/* SQ/RQ DATA byte size is queue depth times entry byte size. */
#define Q_DATA_BSIZE Q_DEPTH *Q_DATA_ENTRY_BSIZE

/* Creates an MKey with proper permissions for access from DPA.
 * For this application, we only need memory write access.
 * Returns pointer to flexio_mkey structure on success. Otherwise, returns NULL.
 * app_ctx - pointer to app_context structure.
 * daddr - address of MKEY data.
 */
static struct flexio_mkey *create_dpa_mkey(struct app_context *app_ctx, flexio_uintptr_t daddr)
{
	/* Flex IO MKey attributes. */
	struct flexio_mkey_attr mkey_attr = {0};
	/* Flex IO MKey. */
	struct flexio_mkey *mkey;

	/* Set MKey protection domain (PD) to the Flex IO process PD. */
	mkey_attr.pd = app_ctx->process_pd;
	/* Set MKey address. */
	mkey_attr.daddr = daddr;
	/* Set MKey length. */
	mkey_attr.len = Q_DATA_BSIZE;
	/* Set MKey access to memory write (from DPA). */
	mkey_attr.access = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE;
	/* Create Flex IO MKey. */
	if (flexio_device_mkey_create(app_ctx->flexio_process, &mkey_attr, &mkey)) {
		printf("Failed to create Flex IO Mkey\n");
		return NULL;
	}

	return mkey;
}

/* CQE size is 64B */
#define CQE_BSIZE 64
#define CQ_BSIZE (Q_DEPTH * CQE_BSIZE)
/* Allocate and initialize DPA heap memory for CQ.
 * Returns 0 on success and -1 if the allocation fails.
 * process - pointer to the previously allocated process information.
 * cq_transf - structure with allocated DPA buffers for CQ.
 */
static int cq_mem_alloc(struct flexio_process *process, struct app_transfer_cq *cq_transf)
{
	/* Pointer to the CQ ring source memory on the host (to copy). */
	struct mlx5_cqe64 *cq_ring_src;
	/* Temp pointer to an iterator for CQE initialization. */
	struct mlx5_cqe64 *cqe;

	/* DBR source memory on the host (to copy). */
	__be32 dbr[2] = { 0, 0 };
	/* Function return value. */
	int ret = 0;
	/* Iterator for CQE initialization. */
	uint32_t i;

	/* Allocate and initialize CQ DBR memory on the DPA heap memory. */
	if (flexio_copy_from_host(process, dbr, sizeof(dbr), &cq_transf->cq_dbr_daddr)) {
		printf("Failed to allocate CQ DBR memory on DPA heap.\n");
		return -1;
	}

	/* Allocate memory for the CQ ring on the host. */
	cq_ring_src = calloc(Q_DEPTH, CQE_BSIZE);
	if (!cq_ring_src) {
		printf("Failed to allocate memory for cq_ring_src.\n");
		return -1;
	}

	/* Init CQEs and set ownership bit. */
	for (i = 0, cqe = cq_ring_src; i < Q_DEPTH; i++)
		mlx5dv_set_cqe_owner(cqe++, 1);

	/* Allocate and copy the initialized CQ ring from host to DPA heap memory. */
	if (flexio_copy_from_host(process, cq_ring_src, CQ_BSIZE, &cq_transf->cq_ring_daddr)) {
		printf("Failed to allocate CQ ring memory on DPA heap.\n");
		ret = -1;
	}

	/* Free CQ ring source memory from host once copied to DPA. */
	free(cq_ring_src);

	return ret;
}

/* SQ WQE byte size is 64B. */
#define LOG_SQ_WQE_BSIZE 6
/* SQ WQE byte size log to value. */
#define SQ_WQE_BSIZE L2V(LOG_SQ_WQE_BSIZE)
/* SQ ring byte size is queue depth times WQE byte size. */
#define SQ_RING_BSIZE (Q_DEPTH * SQ_WQE_BSIZE)
/* Allocate DPA heap memory for SQ.
 * Returns 0 on success and -1 if the allocation fails.
 * process - pointer to the previously allocated process info.
 * sq_transf - structure with allocated DPA buffers for SQ.
 */
static int sq_mem_alloc(struct app_context* app_ctx, struct thread_context* thd_ctx, struct flexio_process *process, struct app_transfer_wq *sq_transf, size_t buffer_location, size_t use_copy, void* buf_addr_if_on_host, uint32_t buf_mkey_if_on_host)
{
	if (buffer_location == 0) {
		if (use_copy == 0) {
			// tmp trick code
			sq_transf->wqd_daddr = thd_ctx->rq_transf.wqd_daddr;
			thd_ctx->sqd_mkey = thd_ctx->rqd_mkey;
			thd_ctx->sq_transf.wqd_mkey_id = thd_ctx->rq_transf.wqd_mkey_id;
		}
		else {
			/* Allocate DPA heap memory for SQ data. */
			flexio_buf_dev_alloc(process, Q_DATA_BSIZE, &sq_transf->wqd_daddr);
			if (!sq_transf->wqd_daddr) {
				return -1;
			}
			/* Create an MKey for SQ data buffer to send. */
			thd_ctx->sqd_mkey = create_dpa_mkey(app_ctx, thd_ctx->sq_transf.wqd_daddr);
			if (!thd_ctx->sqd_mkey) {
				printf("Failed to create an MKey for SQ data buffer\n");
				return -1;
			}
			/* Set SQ's data buffer MKey ID in communication struct. */
			thd_ctx->sq_transf.wqd_mkey_id = flexio_mkey_get_id(thd_ctx->sqd_mkey);
		}
	}
	else {
		if (use_copy == 0) {
			thd_ctx->sq_transf.wqd_daddr = thd_ctx->rq_transf.wqd_daddr;
			thd_ctx->sq_transf.wqd_mkey_id = thd_ctx->rq_transf.wqd_mkey_id;
		}
		else {
			thd_ctx->sq_transf.wqd_daddr = (flexio_uintptr_t) buf_addr_if_on_host;
			thd_ctx->sq_transf.wqd_mkey_id = buf_mkey_if_on_host;
		}
	}
	/* Allocate DPA heap memory for SQ ring. */
	flexio_buf_dev_alloc(process, SQ_RING_BSIZE, &sq_transf->wq_ring_daddr);
	if (!sq_transf->wq_ring_daddr)
		return -1;

	return 0;
}

/* Create an SQ over the DPA for sending packets from DPA to wire.
 * A CQ is also created for the SQ.
 * Returns 0 on success and -1 if the allocation fails.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int create_app_sq(struct app_context *app_ctx, struct thread_context* thd_ctx, size_t buffer_location, size_t use_copy, void* buf_addr_if_on_host, uint32_t buf_mkey_if_on_host)
{
	/* Pointer to the application Flex IO process (ease of use). */
	struct flexio_process *app_fp = app_ctx->flexio_process;
	/* Attributes for the SQ's CQ. */
	struct flexio_cq_attr sqcq_attr = {0};
	/* Attributes for the SQ. */
	struct flexio_wq_attr sq_attr = {0};

	/* UAR ID for CQ/SQ from Flex IO process UAR. */
	uint32_t uar_id = flexio_uar_get_id(app_ctx->process_uar);
	/* SQ's CQ number. */
	uint32_t cq_num;

	/* Allocate CQ memory (ring and DBR) on DPA heap memory. */
	if (cq_mem_alloc(app_fp, &thd_ctx->sq_cq_transf)) {
		printf("Failed to alloc memory for SQ's CQ.\n");
		return -1;
	}

	/* Set CQ depth (log) attribute. */
	sqcq_attr.log_cq_depth = LOG_Q_DEPTH;
	/* Set CQ element type attribute to 'non DPA CQ'.
	 * This means this CQ will not be attached to an event handler.
	 */
	sqcq_attr.element_type = FLEXIO_CQ_ELEMENT_TYPE_NON_DPA_CQ;
	/* Set CQ UAR ID attribute to the Flex IO process UAR ID.
	 * This will allow updating/arming the CQ from the DPA side.
	 */
	sqcq_attr.uar_id = uar_id;
	/* Set CQ DBR memory. DBR memory is on the DPA side in order to allow direct access from
	 * DPA.
	 */
	sqcq_attr.cq_dbr_daddr = thd_ctx->sq_cq_transf.cq_dbr_daddr;
	/* Set CQ ring memory. Ring memory is on the DPA side in order to allow reading CQEs from
	 * DPA during packet forwarding.
	 */
	sqcq_attr.cq_ring_qmem.daddr = thd_ctx->sq_cq_transf.cq_ring_daddr;
	/* Create CQ for SQ. */
	if (flexio_cq_create(app_fp, NULL, &sqcq_attr, &thd_ctx->flexio_sq_cq_ptr)) {
		printf("Failed to create Flex IO CQ\n");
		return -1;
	}

	/* Fetch SQ's CQ number to communicate to DPA side. */
	cq_num = flexio_cq_get_cq_num(thd_ctx->flexio_sq_cq_ptr);
	/* Set SQ's CQ number in communication struct. */
	thd_ctx->sq_cq_transf.cq_num = cq_num;
	/* Set SQ's CQ depth in communication struct. */
	thd_ctx->sq_cq_transf.log_cq_depth = LOG_Q_DEPTH;
	/* Allocate SQ memory (ring and data) on DPA heap memory. */
	if (sq_mem_alloc(app_ctx, thd_ctx, app_fp, &thd_ctx->sq_transf, buffer_location, use_copy, buf_addr_if_on_host, buf_mkey_if_on_host)) {
		printf("Failed to allocate memory for SQ\n");
		return -1;
	}

	/* Set SQ depth (log) attribute. */
	sq_attr.log_wq_depth = LOG_Q_DEPTH;
	/* Set SQ UAR ID attribute to the Flex IO process UAR ID.
	 * This will allow writing doorbells to the SQ from the DPA side.
	 */
	sq_attr.uar_id = uar_id;
	/* Set SQ ring memory. Ring memory is on the DPA side in order to allow writing WQEs from
	 * DPA during packet forwarding.
	 */
	sq_attr.wq_ring_qmem.daddr = thd_ctx->sq_transf.wq_ring_daddr;

	/* Set SQ protection domain */
	sq_attr.pd = app_ctx->process_pd;

	/* Create SQ.
	 * Second argument is NULL as SQ is created on the same GVMI as the process.
	 */
	if (flexio_sq_create(app_fp, NULL, cq_num, &sq_attr, &thd_ctx->flexio_sq_ptr)) {
		printf("Failed to create Flex IO SQ\n");
		return -1;
	}

	/* Fetch SQ's number to communicate to DPA side. */
	thd_ctx->sq_transf.wq_num = flexio_sq_get_wq_num(thd_ctx->flexio_sq_ptr);

	return 0;
}

/* RQ WQE byte size is 64B. */
#define LOG_RQ_WQE_BSIZE 4
/* RQ WQE byte size log to value. */
#define RQ_WQE_BSIZE L2V(LOG_RQ_WQE_BSIZE)
/* RQ ring byte size is queue depth times WQE byte size. */
#define RQ_RING_BSIZE Q_DEPTH *RQ_WQE_BSIZE
/* Allocate DPA heap memory for SQ.
 * Returns 0 on success and -1 if the allocation fails.
 * process - pointer to the previously allocated process info.
 * rq_transf - structure with allocated DPA buffers for RQ.
 */
static int rq_mem_alloc(struct app_context* app_ctx, struct thread_context* thd_ctx, struct flexio_process *process, struct app_transfer_wq *rq_transf, size_t buffer_location, void* buf_addr_if_on_host, uint32_t buf_mkey_if_on_host)
{	
	/* DBR source memory on the host (to copy). */
	__be32 dbr[2] = { 0, 0 };

	if (buffer_location == 0) {
		/* Allocate DPA heap memory for RQ data. */
		flexio_buf_dev_alloc(process, Q_DATA_BSIZE, &rq_transf->wqd_daddr);
		if (!rq_transf->wqd_daddr) {
			return -1;
		}
		/* Create an MKey for RX buffer */
		thd_ctx->rqd_mkey = create_dpa_mkey(app_ctx, thd_ctx->rq_transf.wqd_daddr);
		if (!thd_ctx->rqd_mkey) {
			printf("Failed to create an MKey for RQ data buffer.\n");
			return -1;
		}
		thd_ctx->rq_transf.wqd_mkey_id = flexio_mkey_get_id(thd_ctx->rqd_mkey);
		if (!thd_ctx->rq_transf.wqd_mkey_id) {
			printf("Failed to get mkey id for RQ data buffer.\n");
			return -1;
		}
	}
	else {
		thd_ctx->rq_transf.wqd_daddr = (flexio_uintptr_t) buf_addr_if_on_host;
		thd_ctx->rq_transf.wqd_mkey_id = buf_mkey_if_on_host;
	}
	/* Allocate DPA heap memory for RQ ring. */
	flexio_buf_dev_alloc(process, RQ_RING_BSIZE, &rq_transf->wq_ring_daddr);
	if (!rq_transf->wq_ring_daddr) {
		return -1;
	}

	/* Allocate and initialize RQ DBR memory on the DPA heap memory. */
	flexio_copy_from_host(process, dbr, sizeof(dbr), &rq_transf->wq_dbr_daddr);
	if (!rq_transf->wq_dbr_daddr)
		return -1;

	return 0;
}

/* Initialize an RQ ring memory over the DPA heap memory.
 * RQ WQEs need to be initialized (produced) by SW so they are ready for incoming packets.
 * The WQEs are initialized over temporary host memory and then copied to the DPA.
 * Returns 0 on success and -1 if the allocation fails.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int init_dpa_rq_ring(struct app_context *app_ctx, struct thread_context *thd_ctx)
{
	/* RQ WQE data iterator. */
	flexio_uintptr_t wqe_data_daddr = thd_ctx->rq_transf.wqd_daddr;
	/* RQ ring MKey. */
	uint32_t mkey_id = thd_ctx->rq_transf.wqd_mkey_id;
	/* Temporary host memory for RQ ring. */
	struct mlx5_wqe_data_seg *rx_wqes;
	/* RQ WQE iterator. */
	struct mlx5_wqe_data_seg *dseg;
	/* Function return value. */
	int retval = 0;
	/* RQ WQE index iterator. */
	uint32_t i;

	/* Allocate temporary host memory for RQ ring.*/
	rx_wqes = calloc(1, RQ_RING_BSIZE);
	if (!rx_wqes) {
		printf("Failed to allocate memory for rx_wqes\n");
		return -1;
	}

	/* Initialize RQ WQEs'. */
	for (i = 0, dseg = rx_wqes; i < Q_DEPTH; i++, dseg++) {
		/* Set WQE's data segment to point to the relevant RQ data segment. */
		mlx5dv_set_data_seg(dseg, Q_DATA_ENTRY_BSIZE, mkey_id, wqe_data_daddr);
		/* Advance data pointer to next segment. */
		wqe_data_daddr += Q_DATA_ENTRY_BSIZE;
	}

	/* Copy RX WQEs from host to RQ ring DPA heap memory. */
	if (flexio_host2dev_memcpy(app_ctx->flexio_process, rx_wqes, RQ_RING_BSIZE,
				   thd_ctx->rq_transf.wq_ring_daddr)) {
		retval = -1;
	}

	/* Free temporary host memory. */
	free(rx_wqes);
	return retval;
}

/* Initialize RQ's DBR.
 * Recieve counter need to be set to number of produces WQEs.
 * Returns 0 on success and -1 if the allocation fails.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int init_rq_dbr(struct app_context *app_ctx, struct thread_context * thd_ctx)
{
	/* Temporary host memory for DBR value. */
	__be32 dbr[2];

	/* Set receiver counter to number of WQEs. */
	dbr[0] = htobe32(Q_DEPTH & 0xffff);
	/* Send counter is not used for RQ so it is nullified. */
	dbr[1] = htobe32(0);
	/* Copy DBR value to DPA heap memory.*/
	if (flexio_host2dev_memcpy(app_ctx->flexio_process, dbr, sizeof(dbr),
				   thd_ctx->rq_transf.wq_dbr_daddr)) {
		return -1;
	}

	return 0;
}

/* Create an RQ over the DPA for receiving packets on DPA.
 * A CQ is also created for the RQ.
 * Returns 0 on success and -1 if the allocation fails.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int create_app_rq(struct app_context *app_ctx, struct thread_context* thd_ctx, size_t buffer_location, void* buf_addr_if_on_host, uint32_t buf_mkey_if_on_host)
{
	/* Pointer to the application Flex IO process (ease of use). */
	struct flexio_process *app_fp = app_ctx->flexio_process;
	/* Attributes for the RQ's CQ. */
	struct flexio_cq_attr rqcq_attr = {0};
	/* Attributes for the RQ. */
	struct flexio_wq_attr rq_attr = {0};

	/* UAR ID for CQ/SQ from Flex IO process UAR. */
	uint32_t uar_id = flexio_uar_get_id(app_ctx->process_uar);
	/* RQ's CQ number. */
	uint32_t cq_num;

	/* Allocate CQ memory (ring and DBR) on DPA heap memory. */
	if (cq_mem_alloc(app_fp, &thd_ctx->rq_cq_transf)) {
		printf("Failed to alloc memory for RQ's CQ.\n");
		return -1;
	}

	/* Set CQ depth (log) attribute. */
	rqcq_attr.log_cq_depth = LOG_Q_DEPTH;
	/* Set CQ element type attribute to 'DPA thread'.
	 * This means that a CQE on this CQ will trigger the connetced DPA thread.
	 * This will be used for running the DPA program for each incoming packet on the RQ.
	 */
	rqcq_attr.element_type = FLEXIO_CQ_ELEMENT_TYPE_DPA_THREAD;
	/* Set CQ thread to the application event handler's thread. */
	rqcq_attr.thread = flexio_event_handler_get_thread(thd_ctx->event_handler);
	/* Set CQ UAR ID attribute to the Flex IO process UAR ID.
	 * This will allow updating/arming the CQ from the DPA side.
	 */
	rqcq_attr.uar_id = uar_id;
	/* Set CQ DBR memory. DBR memory is on the DPA side in order to allow direct access from
	 * DPA.
	 */
	rqcq_attr.cq_dbr_daddr = thd_ctx->rq_cq_transf.cq_dbr_daddr;
	/* Set CQ ring memory. Ring memory is on the DPA side in order to allow reading CQEs from
	 * DPA during packet forwarding.
	 */
	rqcq_attr.cq_ring_qmem.daddr = thd_ctx->rq_cq_transf.cq_ring_daddr;
	/* Create CQ for RQ. */
	if (flexio_cq_create(app_fp, NULL, &rqcq_attr, &thd_ctx->flexio_rq_cq_ptr)) {
		printf("Failed to create Flex IO CQ\n");
		return -1;
	}

	/* Fetch SQ's CQ number to communicate to DPA side. */
	cq_num = flexio_cq_get_cq_num(thd_ctx->flexio_rq_cq_ptr);
	/* Set RQ's CQ number in communication struct. */
	thd_ctx->rq_cq_transf.cq_num = cq_num;
	/* Set RQ's CQ depth in communication struct. */
	thd_ctx->rq_cq_transf.log_cq_depth = LOG_Q_DEPTH;
	/* Allocate RQ memory (ring and data) on DPA heap memory. */
	if (rq_mem_alloc(app_ctx, thd_ctx, app_fp, &thd_ctx->rq_transf, buffer_location, buf_addr_if_on_host, buf_mkey_if_on_host)) {
		printf("Failed to allocate memory for RQ.\n");
		return -1;
	}

	// /* Set SQ's data buffer MKey ID in communication struct. */
	// thd_ctx->rq_transf.wqd_mkey_id = flexio_mkey_get_id(thd_ctx->rqd_mkey);
	/* Initialize RQ ring. */
	if (init_dpa_rq_ring(app_ctx, thd_ctx)) {
		printf("Failed to init RQ ring.\n");
		return -1;
	}

	/* Set RQ depth (log) attribute. */
	rq_attr.log_wq_depth = LOG_Q_DEPTH;
	/* Set RQ protection domain attribute to be the same as the Flex IO process. */
	rq_attr.pd = app_ctx->process_pd;
	/* Set RQ DBR memory type to DPA heap memory. */
	rq_attr.wq_dbr_qmem.memtype = FLEXIO_MEMTYPE_DPA;
	/* Set RQ DBR memory address. */
	rq_attr.wq_dbr_qmem.daddr = thd_ctx->rq_transf.wq_dbr_daddr;
	/* Set RQ ring memory address. */
	rq_attr.wq_ring_qmem.daddr = thd_ctx->rq_transf.wq_ring_daddr;
	/* Create the Flex IO RQ.
	 * Second argument is NULL as RQ is created on the same GVMI as the process.
	 */
	if (flexio_rq_create(app_fp, NULL, cq_num, &rq_attr, &thd_ctx->flexio_rq_ptr)) {
		printf("Failed to create Flex IO RQ.\n");
		return -1;
	}

	/* Fetch RQ's number to communicate to DPA side. */
	thd_ctx->rq_transf.wq_num = flexio_rq_get_wq_num(thd_ctx->flexio_rq_ptr);
	if (init_rq_dbr(app_ctx, thd_ctx)) {
		printf("Failed to init RQ DBR.\n");
		return -1;
	}

	return 0;
}

/* Copy application information to DPA.
 * DPA side needs queue information in order to process the packets.
 * The DPA heap memory address will be passed as the event handler argument.
 * Returns 0 if success and -1 if the copy failed.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int copy_app_data_to_dpa(struct app_context *app_ctx, struct thread_context *thd_ctx, int buffer_location, size_t use_copy)
{
	/* Size of application information struct. */
	uint64_t struct_bsize = sizeof(struct host2dev_packet_processor_data);
	/* Temporary application information struct to copy. */
	struct host2dev_packet_processor_data *h2d_data;
	/* Function return value. */
	int ret = 0;

	/* Allocate memory for temporary struct to copy. */
	h2d_data = calloc(1, struct_bsize);
	if (!h2d_data) {
		printf("Failed to allocate memory for h2d_data\n");
		return -1;
	}

	/* Set SQ's CQ information. */
	h2d_data->sq_cq_transf = thd_ctx->sq_cq_transf;
	/* Set SQ's information. */
	h2d_data->sq_transf = thd_ctx->sq_transf;
	/* Set RQ's CQ information. */
	h2d_data->rq_cq_transf = thd_ctx->rq_cq_transf;
	/* Set RQ's information. */
	h2d_data->rq_transf = thd_ctx->rq_transf;
	/* Set APP data info for first run. */
	h2d_data->not_first_run = 0;
	h2d_data->thd_id = thd_ctx->thd_id;
	printf("copied thread id %d\n", h2d_data->thd_id);
	h2d_data->buffer_location = buffer_location;
	h2d_data->use_copy = use_copy;
	h2d_data->window_id = flexio_window_get_id(app_ctx->flexio_window);
	if (h2d_data->window_id == 0) {
		printf("failed to allocate window id.\n");
	}
	h2d_data->result_buffer_mkey_id = thd_ctx->result_buffer_mkey_id;
	h2d_data->result_buffer = thd_ctx->result_buffer;

	/* Copy to DPA heap memory.
	 * Allocated DPA heap memory address will be kept in app_data_daddr.
	 */
	if (flexio_copy_from_host(app_ctx->flexio_process, h2d_data, struct_bsize,
				  &thd_ctx->app_data_daddr)) {
		printf("Failed to copy application information to DPA.\n");
		ret = -1;
	}

	/* Free temporary host memory. */
	free(h2d_data);
	return ret;
}

/* Clean up previously allocated RQ
 * Returns 0 on success and -1 if the destroy failed.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int clean_up_app_rq(struct app_context* app_ctx, struct thread_context *thd_ctx)
{
	int err = 0;

	/* Clean up rq pointer if created */
	if (thd_ctx->flexio_rq_ptr && flexio_rq_destroy(thd_ctx->flexio_rq_ptr)) {
		printf("Failed to destroy RQ\n");
		err = -1;
	}

	/* Clean up memory key for rqd if created */
	if (thd_ctx->rqd_mkey && flexio_device_mkey_destroy(thd_ctx->rqd_mkey)) {
		printf("Failed to destroy mkey RQD\n");
		err = -1;
	}

	/* Clean up app data daddr if created */
	if (thd_ctx->rq_transf.wq_dbr_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, thd_ctx->rq_transf.wq_dbr_daddr)) {
		printf("Failed to free rq_transf.wq_dbr_daddr\n");
		err = -1;
	}

	/* Clean up wq_ring_daddr for rq_transf if created */
	if (thd_ctx->rq_transf.wq_ring_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, thd_ctx->rq_transf.wq_ring_daddr)) {
		printf("Failed to free rq_transf.wq_ring_daddr\n");
		err = -1;
	}

	if (thd_ctx->rq_transf.wqd_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, thd_ctx->rq_transf.wqd_daddr)) {
		printf("Failed to free rq_transf.wqd_daddr\n");
		err = -1;
	}

	if (thd_ctx->flexio_rq_cq_ptr && flexio_cq_destroy(thd_ctx->flexio_rq_cq_ptr)) {
		printf("Failed to destroy RQ' CQ\n");
		err = -1;
	}

	if (thd_ctx->rq_cq_transf.cq_ring_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, thd_ctx->rq_cq_transf.cq_ring_daddr)) {
		printf("Failed to free rq_cq_transf.cq_ring_daddr\n");
		err = -1;
	}

	if (thd_ctx->rq_cq_transf.cq_dbr_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, thd_ctx->rq_cq_transf.cq_dbr_daddr)) {
		printf("Failed to free rq_cq_transf.cq_dbr_daddr\n");
		err = -1;
	}

	return err;
}

/* Clean up previously allocated SQ
 * Returns 0 on success and -1 if the destroy failed.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int clean_up_app_sq(struct app_context* app_ctx, struct thread_context *thd_ctx)
{
	int err = 0;

	if (thd_ctx->flexio_sq_ptr && flexio_sq_destroy(thd_ctx->flexio_sq_ptr)) {
		printf("Failed to destroy SQ\n");
		err = -1;
	}

	if (thd_ctx->sqd_mkey && flexio_device_mkey_destroy(thd_ctx->sqd_mkey)) {
		printf("Failed to destroy mkey SQD\n");
		err = -1;
	}

	if (thd_ctx->sq_transf.wq_ring_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, thd_ctx->sq_transf.wq_ring_daddr)) {
		printf("Failed to free sq_transf.wq_ring_daddr\n");
		err = -1;
	}

	if (thd_ctx->sq_transf.wqd_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, thd_ctx->sq_transf.wqd_daddr)) {
		printf("Failed to free sq_transf.wqd_daddr\n");
		err = -1;
	}

	if (thd_ctx->flexio_sq_cq_ptr && flexio_cq_destroy(thd_ctx->flexio_sq_cq_ptr)) {
		printf("Failed to destroy SQ' CQ\n");
		err = -1;
	}

	if (thd_ctx->sq_cq_transf.cq_ring_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, thd_ctx->sq_cq_transf.cq_ring_daddr)) {
		printf("Failed to free sq_cq_transf.cq_ring_daddr\n");
		err = -1;
	}

	if (thd_ctx->sq_cq_transf.cq_dbr_daddr &&
	    flexio_buf_dev_free(app_ctx->flexio_process, thd_ctx->sq_cq_transf.cq_dbr_daddr)) {
		printf("Failed to free sq_cq_transf.cq_dbr_daddr\n");
		err = -1;
	}


	return err;
}


size_t threads_num = 1;

size_t begin_thread = 0;

uint64_t DMAC = 0xa088c2320440;

size_t buffer_location = 0;

size_t use_copy = 1;
/* dev msg stream buffer built from chunks of 2^FLEXIO_MSG_DEV_LOG_DATA_CHUNK_BSIZE each */
#define MSG_HOST_BUFF_BSIZE (512 * L2V(FLEXIO_MSG_DEV_LOG_DATA_CHUNK_BSIZE))

#define MR_BASE_ALIGNMENT 64				/* Memory alignment required for window buffers */

#define nic_mode 1
/* Main host side function.
 * Responsible for allocating resources and making preparations for DPA side envocatin.
 */
int main(int argc, char **argv)
{
    if (argc > 2) {
        threads_num = atoi(argv[2]);
    }

	if (argc > 3) {
        begin_thread = atoi(argv[3]);
    }

	if (argc > 4) {
        DMAC = strtoull(argv[4], NULL, 16);
    }

	if (argc > 5) {
		buffer_location = atoi(argv[5]);
	}

	if (argc > 6) {
		use_copy = atoi(argv[6]);
	}

	char buf[2];
	int err = 0;
	flexio_status ret = 0;
	struct flexio_process_attr process_attr = { NULL, 0 };
	struct app_context app_ctx = {};
	struct thread_context* thd_ctx = NULL;
	struct mlx5dv_dr_domain* rx_dr = NULL;
	struct mlx5dv_dr_domain* tx_dr = NULL;

	struct mlx5dv_flow_match_parameters *match_mask = NULL;
	int match_mask_size = 0;
	struct mlx5dv_dr_table* rx_dr_table_root = NULL;
	struct mlx5dv_dr_matcher* rx_dr_matcher_root = NULL;
	struct mlx5dv_dr_table* tx_dr_table_root = NULL;
	struct mlx5dv_dr_matcher* tx_dr_matcher_root = NULL;
	struct mlx5dv_dr_table* tx_dr_table_sws = NULL;
	struct mlx5dv_dr_matcher* tx_dr_matcher_sws = NULL;

	void* rqd_daddr_if_buffer_on_host = NULL;
	void* sqd_daddr_if_buffer_on_host = NULL;
	uint32_t rqd_daddr_mkey_id = 0;
	uint32_t sqd_daddr_mkey_id = 0;

	thd_ctx = malloc(sizeof(struct thread_context) * threads_num);
	if (thd_ctx == NULL) {
		printf("malloc thread context failed\n");
		return -1;
	}

	printf("Welcome to 'Flex IO SDK packet processing' sample app.\n");

	if (geteuid()) {
		printf("Failed - the application must run with root privileges\n");
		return -1;
	}

	err = app_open_ibv_ctx(&(app_ctx), argv[1]);
	if (err) {
		printf("Failed to open ibv context.\n");
		return -1;
		goto cleanup;
	}

	if (flexio_process_create(app_ctx.ibv_ctx, DEV_APP_NAME, &process_attr, &(app_ctx.flexio_process))) {
		printf("Failed to create Flex IO process.\n");
		err = -1;
		goto cleanup;
	}

	app_ctx.process_pd = ibv_alloc_pd(app_ctx.ibv_ctx);
	if (app_ctx.process_pd == NULL) {
		printf("Failed to create pd.\n");
		err = -1;
		goto cleanup;
	}

	ret = flexio_window_create(app_ctx.flexio_process, app_ctx.process_pd, &(app_ctx.flexio_window));
	if (ret != FLEXIO_STATUS_SUCCESS) {
		printf("Failed to create FlexIO window\n");
		err = -1;
		goto cleanup;
	}

	app_ctx.process_uar = flexio_process_get_uar(app_ctx.flexio_process);

	flexio_msg_stream_attr_t stream_fattr = {0};
	stream_fattr.uar = app_ctx.process_uar;
	stream_fattr.data_bsize = 4 * 2048;
	stream_fattr.sync_mode = FLEXIO_LOG_DEV_SYNC_MODE_SYNC;
	stream_fattr.level = FLEXIO_MSG_DEV_DEBUG;
	stream_fattr.stream_name = "Default Stream";
	stream_fattr.mgmt_affinity.type = FLEXIO_AFFINITY_NONE;
	if (flexio_msg_stream_create(app_ctx.flexio_process, &stream_fattr, stdout, NULL,
						&(app_ctx.stream))) {
		printf("Failed to init device messaging environment, exiting App\n");
		err = -1;
		goto cleanup;
	}


	rx_dr = mlx5dv_dr_domain_create(app_ctx.ibv_ctx, MLX5DV_DR_DOMAIN_TYPE_NIC_RX);
	if (!rx_dr) {
		printf("Fail creating dr_domain (errno %d)\n", errno);
		goto cleanup;
	}
#ifndef nic_mode
	tx_dr = mlx5dv_dr_domain_create(app_ctx.ibv_ctx, MLX5DV_DR_DOMAIN_TYPE_FDB);
	if (!tx_dr) {
		printf("Fail creating dr_domain (errno %d)\n", errno);
		goto cleanup;
	}
#endif

	match_mask_size = sizeof(*match_mask) + MATCH_VAL_BSIZE;
	match_mask = (struct mlx5dv_flow_match_parameters *)calloc(1, match_mask_size);
	if (!match_mask) {
		printf("allocate  match mask failed\n");
		goto cleanup;
	}

	match_mask->match_sz = MATCH_VAL_BSIZE;
	DEVX_SET(dr_match_spec, match_mask->match_buf, dmac_47_16, 0xffffffff);
	DEVX_SET(dr_match_spec, match_mask->match_buf, dmac_15_0, 0xffff);

	rx_dr_table_root = mlx5dv_dr_table_create(rx_dr, 0);
	if (!rx_dr_table_root) {
		printf("Fail creating dr_table (errno %d)\n", errno);
		goto cleanup;
	}

	rx_dr_matcher_root = mlx5dv_dr_matcher_create(rx_dr_table_root, 0, 1, match_mask);
	if (!rx_dr_matcher_root) {
		printf("Fail creating dr_matcher (errno %d)\n", errno);
		goto cleanup;
	}

	memset(match_mask->match_buf, 0, MATCH_VAL_BSIZE);


#ifndef nic_mode
	DEVX_SET(dr_match_spec, match_mask->match_buf, smac_47_16, 0xffffffff);
	DEVX_SET(dr_match_spec, match_mask->match_buf, smac_15_0, 0xffff);

	tx_dr_table_root = mlx5dv_dr_table_create(tx_dr, 0);
	if (!tx_dr_table_root) {
		printf("Fail creating dr_table (errno %d)\n", errno);
		goto cleanup;
	}
	tx_dr_matcher_root = mlx5dv_dr_matcher_create(tx_dr_table_root, 0, 1, match_mask);
	if (!tx_dr_matcher_root) {
		printf("Fail creating dr_matcher (errno %d)\n", errno);
		goto cleanup;
	}

	tx_dr_table_sws = mlx5dv_dr_table_create(tx_dr, 1);
	if (!tx_dr_table_sws) {
		printf("Fail creating dr_table (errno %d)\n", errno);
		goto cleanup;
	}
	tx_dr_matcher_sws = mlx5dv_dr_matcher_create(tx_dr_table_sws, 0, 1, match_mask);
	if (!tx_dr_matcher_sws) {
		printf("Fail creating dr_matcher (errno %d)\n", errno);
		goto cleanup;
	}

	memset(match_mask->match_buf, 0, MATCH_VAL_BSIZE);
#endif

    // DMAC += begin_thread;

    // int core_id[190];
    // int cur = 0;
    // int next_first= 1;
    // for (int i = 0; i < 190; i++) {
    //     core_id[i] = cur;
    //     cur += 16;
    //     if (cur >= 190) {
    //         cur = next_first;
    //         next_first++;
    //     }
    // }

	for (int i = 0; i < threads_num; i++) {
		struct flexio_event_handler_attr handler_attr = {0};
		struct mlx5dv_flow_match_parameters *match_value = 0;
		int match_value_size;
		uint64_t cur_dmac = DMAC + begin_thread + i;
		// uint64_t cur_dmac = DMAC;
		printf("%lx\n", cur_dmac);

        handler_attr.host_stub_func = flexio_pp_dev;
		// handler_attr.affinity.type = FLEXIO_AFFINITY_NONE;
        handler_attr.affinity.type = FLEXIO_AFFINITY_STRICT;
        handler_attr.affinity.id = i + begin_thread;
        ret = flexio_event_handler_create(app_ctx.flexio_process, &handler_attr, &(thd_ctx[i].event_handler));
        if (ret != FLEXIO_STATUS_SUCCESS) {
			printf("Fail tp create event handler.\n");
			goto cleanup;
		}
		if (buffer_location == 0) {
			void* tmp_ptr = NULL;
			size_t needed_buffer_size = SPEED_RESULT_SIZE;
			size_t mmap_size = needed_buffer_size + (64 - 1);
			mmap_size -= mmap_size % 64;
			tmp_ptr = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
			if (tmp_ptr == NULL) {
				printf("Failed to allocate host buffer\n");
				return -1;
			}
			memset(tmp_ptr, 0, mmap_size);
			thd_ctx[i].mr = ibv_reg_mr(app_ctx.process_pd, tmp_ptr, mmap_size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
			if (thd_ctx[i].mr == NULL) {
				printf("Failed to register MR\n");
				return -1;
			}
			thd_ctx[i].result_buffer_mkey_id = thd_ctx[i].mr->lkey;
			thd_ctx[i].result_buffer = (char*)tmp_ptr;
		}
		else {
			void* tmp_ptr = NULL;
			size_t needed_buffer_size = 2 * Q_DATA_BSIZE + SPEED_RESULT_SIZE;
			size_t mmap_size = needed_buffer_size + (64 - 1);
			mmap_size -= mmap_size % 64;
			tmp_ptr = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
			if (tmp_ptr == NULL) {
				printf("Failed to allocate host buffer\n");
				return -1;
			}
			memset(tmp_ptr, 0, mmap_size);
			thd_ctx[i].mr = ibv_reg_mr(app_ctx.process_pd, tmp_ptr, mmap_size, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
			if (thd_ctx[i].mr == NULL) {
				printf("Failed to register MR\n");
				return -1;
			}
			rqd_daddr_if_buffer_on_host = tmp_ptr;
			sqd_daddr_if_buffer_on_host = (char*)tmp_ptr + Q_DATA_BSIZE;
			sqd_daddr_mkey_id = thd_ctx[i].mr->lkey;
			rqd_daddr_mkey_id = thd_ctx[i].mr->lkey;
			thd_ctx[i].result_buffer_mkey_id = thd_ctx[i].mr->lkey;
			thd_ctx[i].result_buffer = (char*)tmp_ptr + 2 * Q_DATA_BSIZE;
		}

		if (create_app_rq(&(app_ctx), &(thd_ctx[i]), buffer_location, rqd_daddr_if_buffer_on_host, rqd_daddr_mkey_id)) {
			printf("Failed to create Flex EQ.\n");
			err = -1;
			goto cleanup;
		}

		if (create_app_sq(&(app_ctx), &(thd_ctx[i]), buffer_location, use_copy, sqd_daddr_if_buffer_on_host, sqd_daddr_mkey_id)) {
			printf("Failed to create Flex SQ.\n");
			err = -1;
			goto cleanup;
		}
	
		match_value_size = sizeof(*match_value) + MATCH_VAL_BSIZE;
		match_value = (struct mlx5dv_flow_match_parameters *)calloc(1, match_value_size);
		if (match_value == NULL) {
			printf("allocate match_value failed\n");
			goto cleanup;
		}
	
		match_value->match_sz = MATCH_VAL_BSIZE;
		DEVX_SET(dr_match_spec, match_value->match_buf, dmac_47_16, cur_dmac >> 16);
		DEVX_SET(dr_match_spec, match_value->match_buf, dmac_15_0, cur_dmac % (1 << 16));

		thd_ctx[i].rq_tir_obj = flexio_rq_get_tir(thd_ctx[i].flexio_rq_ptr);
		if (thd_ctx[i].rq_tir_obj == NULL) {
			printf("Fail creating rq_tir_obj (errno %d)\n", errno);
			goto cleanup;
		}

		thd_ctx[i].rq_action = mlx5dv_dr_action_create_dest_devx_tir(thd_ctx[i].rq_tir_obj);
		if (thd_ctx[i].rq_action == NULL) {
			printf("Fail creating rq_action (errno %d)\n", errno);
			goto cleanup;
		}

		thd_ctx[i].rx_dr_rule = mlx5dv_dr_rule_create(rx_dr_matcher_root, match_value, 1, &(thd_ctx[i].rq_action));
		if (thd_ctx[i].rx_dr_rule == NULL) {
			printf("Fail creating rx_dr_rule (errno %d)\n", errno);
			goto cleanup;
		}

		memset(match_value->match_buf, 0, MATCH_VAL_BSIZE);
		
#ifndef nic_mode

		DEVX_SET(dr_match_spec, match_value->match_buf, smac_47_16, cur_dmac >> 16);
		DEVX_SET(dr_match_spec, match_value->match_buf, smac_15_0, cur_dmac % (1 << 16));
	
		thd_ctx[i].tx_action = mlx5dv_dr_action_create_dest_table(tx_dr_table_sws);
		if (!thd_ctx[i].tx_action) {
			printf("Failed creating dest SWS table action (errno %d).\n", errno);
			goto cleanup;
		}
	
		thd_ctx[i].tx_dr_rule = mlx5dv_dr_rule_create(tx_dr_matcher_root, match_value, 1, &(thd_ctx[i].tx_action));
		if (!thd_ctx[i].tx_dr_rule) {
			printf("Fail creating dr_rule (errno %d).\n", errno);
			goto cleanup;
		}

		thd_ctx[i].tx_action2 = mlx5dv_dr_action_create_dest_vport(tx_dr, 0xFFFF);
		if (!thd_ctx[i].tx_action2) {
			printf("Failed creating dest SWS table action (errno %d).\n", errno);
			goto cleanup;
		}
	
		thd_ctx[i].tx_dr_rule2 = mlx5dv_dr_rule_create(tx_dr_matcher_sws, match_value, 1, &(thd_ctx[i].tx_action2));
		if (!thd_ctx[i].tx_dr_rule2) {
			printf("Fail creating dr_rule (errno %d).\n", errno);
			goto cleanup;
		}

		memset(match_value->match_buf, 0, MATCH_VAL_BSIZE);

#endif
		thd_ctx[i].thd_id = i;
		if (copy_app_data_to_dpa(&app_ctx, &(thd_ctx[i]), buffer_location, use_copy)) {
			printf("Failed to copy application data to DPA.\n");
			err = -1;
			goto cleanup;
		}

		if (flexio_event_handler_run(thd_ctx[i].event_handler, thd_ctx[i].app_data_daddr)) {
			printf("Failed to run event handler.\n");
			err = -1;
			goto cleanup;
		}

	}

	// while (1) {
	// 	sleep(3);
	// 	uint64_t sum = 0;
	// 	for (int i = 0; i < threads_num; i++) {
	// 		printf("addr: 0x%p, value: %lu\n", thd_ctx[i].result_buffer, *((uint64_t*)thd_ctx[i].result_buffer));
	// 		sum += *((uint64_t*)thd_ctx[i].result_buffer);
	// 	}
	// 	printf("sum speed %luMbps\n", sum);
	// }

	/* Wait for Enter - the DPA sample is running in the meanwhile */
	if (!fread(buf, 1, 1, stdin)) {
		printf("Failed in fread\n");
	}

cleanup:
	/* Clean up flow is done in reverse order of creation as there's a refernce system
	 * that won't allow destroying resources that has references to existing resources.
	 */

	for (size_t i = 0; i < threads_num; i++) {    
        if (thd_ctx[i].app_data_daddr && flexio_buf_dev_free(app_ctx.flexio_process, thd_ctx[i].app_data_daddr)) {
    	    printf("Failed to dealloc application data memory on Flex IO heap\n");
        }
    }

	for (size_t i = 0; i < threads_num; i++) { 

        /* Clean up rx rule if created */
        if (thd_ctx[i].rx_dr_rule) {
            if (mlx5dv_dr_rule_destroy(thd_ctx[i].rx_dr_rule)) {
                printf("Failed to destroy rx rule\n");
            }
        }

        if (thd_ctx[i].rq_action) {
			if (mlx5dv_dr_action_destroy(thd_ctx[i].rq_action)) {
				printf("Failed to destroy rx rule\n");
			}
        }
    }

    if (rx_dr_matcher_root) {
        if (mlx5dv_dr_matcher_destroy(rx_dr_matcher_root)) {
            printf("Failed to destroy rx matcher\n");
        }
    }

    if (rx_dr_table_root) {
        if (mlx5dv_dr_table_destroy(rx_dr_table_root)) {
            printf("Failed to destroy rx table\n");
        }
    }

    if (rx_dr) {
        if (mlx5dv_dr_domain_destroy(rx_dr)) {
            printf("Failed to destroy rx dr\n");
        }
    }

    for (size_t i = 0; i < threads_num; i++) { 
        /* Clean up rx rule if created */
        if (thd_ctx[i].tx_dr_rule2) {
            if (mlx5dv_dr_rule_destroy(thd_ctx[i].tx_dr_rule2)) {
                printf("Failed to destroy tx rule\n");
            }
        }

        if (thd_ctx[i].tx_action2) {
			if (mlx5dv_dr_action_destroy(thd_ctx[i].tx_action2)) {
				printf("Failed to destroy tx rule\n");
			}
        }
        if (thd_ctx[i].tx_dr_rule) {
            if (mlx5dv_dr_rule_destroy(thd_ctx[i].tx_dr_rule)) {
                printf("Failed to destroy tx root rule\n");
            }
        }

        if (thd_ctx[i].tx_action) {
			if (mlx5dv_dr_action_destroy(thd_ctx[i].tx_action)) {
				printf("Failed to destroy tx root rule\n");
			}
        }
    }

    if (tx_dr_matcher_sws) {
        if (mlx5dv_dr_matcher_destroy(tx_dr_matcher_sws)) {
            printf("Failed to destroy rx matcher\n");
        }
    }

    if (tx_dr_table_sws) {
        if (mlx5dv_dr_table_destroy(tx_dr_table_sws)) {
            printf("Failed to destroy rx table\n");
        }
    }

    if (tx_dr_matcher_root) {
        if (mlx5dv_dr_matcher_destroy(tx_dr_matcher_root)) {
            printf("Failed to destroy rx matcher\n");
        }
    }

    if (tx_dr_table_root) {
        if (mlx5dv_dr_table_destroy(tx_dr_table_root)) {
            printf("Failed to destroy rx table\n");
        }
    }

    if (tx_dr) {
        if (mlx5dv_dr_domain_destroy(tx_dr)) {
            printf("Failed to destroy tx dr\n");
        }
    }
	for (size_t i = 0; i < threads_num; i++) {
		/* Clean up previously allocated SQ */
		if (clean_up_app_sq(&app_ctx, &(thd_ctx[i]))) {
            printf("Failed to destroy sq\n");
		}

		/* Clean up previously allocated RQ */
		if (clean_up_app_rq(&app_ctx, &(thd_ctx[i]))) {
            printf("Failed to destroy cq\n");
		}
		if (thd_ctx[i].event_handler && flexio_event_handler_destroy(thd_ctx[i].event_handler)) {
            printf("Failed to destroy event handler\n");
		}
	}

	if (app_ctx.stream && flexio_msg_stream_destroy(app_ctx.stream)) {
		printf("Failed to destroy device messaging environment\n");
	}

	if (app_ctx.flexio_window && flexio_window_destroy(app_ctx.flexio_window)) {
		printf("Failed to destroy window.\n");
	}

	if (app_ctx.flexio_process && flexio_process_destroy(app_ctx.flexio_process)) {
		printf("Failed to destroy process.\n");
	}

	/* Close the IBV device */
	if (app_ctx.ibv_ctx && ibv_close_device(app_ctx.ibv_ctx)) {
		printf("Failed to close ibv context.\n");
	}

	return err;
}
