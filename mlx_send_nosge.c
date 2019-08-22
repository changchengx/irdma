/*
* Build Command:
* $ gcc -Wall -O2 -o beacon_nosge mlx_send_nosge.c -libverbs -lrdmacm
*
* Run:
* 1) On server side (server RNIC ip: 192.168.199.222, assume TCP port 9786, use NIC 1st port, the first(0)GID)
* $ ./beacon_nosge -p 9786 -d rocep4s0 -i 1 -g 0
* Log:
*       19-08-21 13:02:42.492794 nstcc1@nstcloudcc1:irdma$ nstcc1@nstcloudcc1:irdma$ ./beacon_nosge -p 9786 -d rocep4s0 -i 1 -g 0
*       19-08-21 13:02:42.503611  ------------------------------------------------
*       19-08-21 13:02:42.503988  Device name : "rocep4s0"
*       19-08-21 13:02:42.504161  IB port : 1
*       19-08-21 13:02:42.504322  TCP port : 9786
*       19-08-21 13:02:42.504477  GID index : 0
*       19-08-21 13:02:42.504565  ------------------------------------------------
*       19-08-21 13:02:42.504643
*       19-08-21 13:02:42.504731 waiting on port 9786 for TCP connection
*       19-08-21 13:02:52.841819 TCP connection was established
*       19-08-21 13:02:52.841999 searching for IB devices in host
*       19-08-21 13:02:52.856715 found 5 device(s)
*       19-08-21 13:02:52.859964 going to send the message: 'SEND operation '
*       19-08-21 13:02:52.860212 MR was registered with addr=0x557fda49eba0, lkey=0xd0010237, rkey=0xd0010237, flags=0x7
*       19-08-21 13:02:52.860469 QP was created, QP number=0x2b04
*       19-08-21 13:02:52.860562 *********begin connect qp***********
*       19-08-21 13:02:52.860647
*       19-08-21 13:02:52.860731 Local LID = 0x0 
*       19-08-21 13:02:52.860878 Remote address = 0x55c362eb1ba0
*       19-08-21 13:02:52.860966 Remote rkey = 0xd0010137
*       19-08-21 13:02:52.861043 Local QP number = 0x2b04
*       19-08-21 13:02:52.861119 Remote QP number = 0x2b03
*       19-08-21 13:02:52.861195 Remote LID = 0x0 
*       19-08-21 13:02:52.861272 Remote GID = fe:80:00:00:00:00:00:00:26:8a:07:ff:fe:60:90:e0
*       19-08-21 13:02:52.861880 QP state was change to RTS
*       19-08-21 13:02:52.862252 *********qp connected***********
*       19-08-21 13:02:52.862355 **********server begin send beacon************
*       19-08-21 13:02:52.862434 Send Request was posted
*       19-08-21 13:02:52.862512 completion was found in CQ with status 0x0
*       19-08-21 13:02:52.862589  ibv_wc wr_id: 0xdeadbeef, status:0x0, opcode: 0x0, byte_len: 0x0, local qp number: 0x2b04, remote qp number: 0x0
*       19-08-21 13:02:52.862666 ***********all finish the poll completion***********
*       19-08-21 13:02:52.864400
*       19-08-21 13:02:52.864554 test result is 0
*
* 2) On client side
* $ ./beacon_nosge -p 9786 -d rocep4s0 -i 1 -g 0 192.168.199.222
* Log:
*       19-08-21 13:02:52.840402 nstcc1@nstcloudcc1:irdma$ ./beacon_nosge -p 9786 -d rocep4s0 -i 1 -g 0 192.168.199.222
*       19-08-21 13:02:52.840518  ------------------------------------------------
*       19-08-21 13:02:52.840686  Device name : "rocep4s0"
*       19-08-21 13:02:52.840786  IB port : 1
*       19-08-21 13:02:52.840880  IP : 192.168.199.222
*       19-08-21 13:02:52.840973  TCP port : 9786
*       19-08-21 13:02:52.841065  GID index : 0
*       19-08-21 13:02:52.841158  ------------------------------------------------
*       19-08-21 13:02:52.841251
*       19-08-21 13:02:52.841570 TCP connection was established
*       19-08-21 13:02:52.841683 searching for IB devices in host
*       19-08-21 13:02:52.853604 found 5 device(s)
*       19-08-21 13:02:52.855399 MR was registered with addr=0x55c362eb1ba0, lkey=0xd0010137, rkey=0xd0010137, flags=0x7
*       19-08-21 13:02:52.859919 QP was created, QP number=0x2b03
*       19-08-21 13:02:52.860093 *********begin connect qp***********
*       19-08-21 13:02:52.860202
*       19-08-21 13:02:52.860299 Local LID = 0x0 
*       19-08-21 13:02:52.861003 Remote address = 0x557fda49eba0
*       19-08-21 13:02:52.861159 Remote rkey = 0xd0010237
*       19-08-21 13:02:52.861262 Local QP number = 0x2b03
*       19-08-21 13:02:52.861357 Remote QP number = 0x2b04
*       19-08-21 13:02:52.861521 Remote LID = 0x0 
*       19-08-21 13:02:52.861632 Remote GID = fe:80:00:00:00:00:00:00:26:8a:07:ff:fe:60:90:e0
*       19-08-21 13:02:52.861737 Receive Request was posted
*       19-08-21 13:02:52.861976 QP state was change to RTS
*       19-08-21 13:02:52.862164 *********qp connected***********
*       19-08-21 13:02:52.862283 **********server begin send beacon************
*       19-08-21 13:02:52.862382 completion was found in CQ with status 0x0
*       19-08-21 13:02:52.862475  ibv_wc wr_id: 0x0, status:0x0, opcode: 0x80, byte_len: 0x0, local qp number: 0x2b03, remote qp number: 0x0
*       19-08-21 13:02:52.862575 ***********all finish the poll completion***********
*       19-08-21 13:02:52.865036
*       19-08-21 13:02:52.865205 test result is 0
*/
/******************************************************************************
*
* This code demonstrates how to perform the following operations using the * VPI Verbs API:
*
* Send
* Receive
* RDMA Read
* RDMA Write
*
*****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <endian.h>
#include <byteswap.h>
#include <getopt.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* poll CQ timeout in millisec (2 seconds) */
#define MAX_POLL_CQ_TIMEOUT 2000
#define MSG "SEND operation "
#define RDMAMSGR "RDMA read operation "
#define RDMAMSGW "RDMA write operation"
#define MSG_SIZE (strlen(MSG) + 1)
#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) { return bswap_64(x); }
static inline uint64_t ntohll(uint64_t x) { return bswap_64(x); }
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x) { return x; }
static inline uint64_t ntohll(uint64_t x) { return x; }
#else
#error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

/* structure to exchange data which is needed to connect the QPs */
struct cm_con_data_t
{
	uint64_t addr;                       /* Buffer address */
	uint32_t rkey;                       /* Remote key */
	uint32_t qp_num;                     /* QP number */
	uint16_t lid;                        /* LID of the IB port */
	uint8_t gid[16];                     /* gid */
}__attribute__((packed));

/* structure of system resources */
struct resources
{
	struct ibv_device_attr device_attr;  /* Device attributes */
	struct ibv_port_attr port_attr;      /* IB port attributes */
	struct cm_con_data_t remote_props;   /* values to connect to remote side */
	struct ibv_context *ib_ctx;          /* device handle */
	struct ibv_pd *pd;                   /* PD handle */
	struct ibv_cq *cq;                   /* CQ handle */
	struct ibv_qp *qp;                   /* QP handle */
	struct ibv_mr *mr;                   /* MR handle for buf */
	char *buf;                           /* memory buffer pointer, used for RDMA and send ops */
	int sock;                            /* TCP socket file descriptor */
};

/* structure of test parameters */
struct config_t
{
	const char *dev_name;    /* IB device name */
	char *server_name;       /* server host name */
	u_int32_t tcp_port;      /* server TCP port */
	int ib_port;             /* local IB port to work with */
	int gid_idx;             /* gid index to use */
};

struct config_t config =
{
	NULL,                                /* dev_name */
	NULL,                                /* server_name */
	19875,                               /* tcp_port */
	1,                                   /* ib_port */
	-1                                   /* gid_idx */
};

/******************************************************************************
Socket operations
For simplicity, the example program uses TCP sockets to exchange control
information. If a TCP/IP stack/connection is not available, connection manager
(CM) may be used to pass this information. Use of CM is beyond the scope of
this example
******************************************************************************/
/******************************************************************************
* Function: sock_connect
*
* Input
* nodename: URL of server to connect to (NULL for server mode)
* port: port of service
*
* Output
* none
*
* Returns
* socket (fd) on success, negative error code on failure
*
* Description
* Connect a socket.
* If nodename is specified,  a client connection will be initiated to the indicated server and port.
* Otherwise listen on the indicated port for an incoming connection.
*
******************************************************************************/
static int sock_connect(const char *nodename, int port)
{
	struct addrinfo *resolved_addr = NULL;
	struct addrinfo *iterator = NULL;
	char service[6] = {0};
	int sockfd = -1;
	int listenfd = 0;

	struct addrinfo hints =
	{
		.ai_flags = AI_PASSIVE,
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 0
	};

	if (sprintf(service, "%d", port) < 0)
		goto sock_connect_exit;

	/* Resolve DNS address, use sockfd as temp storage */
	sockfd = getaddrinfo(nodename, service, &hints, &resolved_addr);
	if (sockfd != 0) {
		fprintf(stderr, "%s for %s:%d\n", gai_strerror(sockfd), nodename, port);
		goto sock_connect_exit;
	}

	/* Search through results and find the one we want */
	for (iterator = resolved_addr; iterator ; iterator = iterator->ai_next) {
		sockfd = socket(iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol);
		if (sockfd >= 0) {
			if (nodename) {
				/* Client mode. Initiate connection to remote */
				if (connect(sockfd, iterator->ai_addr, iterator->ai_addrlen) != 0) {
					fprintf(stdout, "failed connect \n");
					close(sockfd);
					sockfd = -1;
				}
			} else {
				/* Server mode. Set up listening socket to accept a connection */
				listenfd = sockfd;
				sockfd = -1;
				if(bind(listenfd, iterator->ai_addr, iterator->ai_addrlen) != 0)
					goto sock_connect_exit;
				listen(listenfd, 1);
				sockfd = accept(listenfd, NULL, 0);
			}
		}
	}

sock_connect_exit:
	if(listenfd)
		close(listenfd);
	if(resolved_addr)
		freeaddrinfo(resolved_addr);
	if (sockfd < 0) {
		if(nodename)
			fprintf(stderr, "Couldn't connect to %s:%d\n", nodename, port);
		else {
			perror("server accept");
			fprintf(stderr, "accept() failed\n");
		}
	}
	return sockfd;
}
/******************************************************************************
* Function: sock_sync_data
*
* Input
* sock: socket to transfer data on
* xfer_size: size of data to transfer
* local_data: pointer to data to be sent to remote
*
* Output
* remote_data pointer to buffer to receive remote data
*
* Returns
* 0 on success, negative error code on failure
*
* Description
* Sync data across a socket. The indicated local data will be sent to the
* remote. It will then wait for the remote to send its data back. It is
* assumed that the two sides are in sync and call this function in the proper
* order. Chaos will ensue if they are not. :)
*
* Also note this is a blocking function and will wait for the full data to be
* received from the remote.
*
******************************************************************************/
int sock_sync_data(int sock, int xfer_size, char *local_data, char *remote_data)
{
	int rc;
	int read_bytes = 0;
	int total_read_bytes = 0;

	rc = write(sock, local_data, xfer_size);
	if(rc < xfer_size)
		fprintf(stderr, "Failed writing data during sock_sync_data\n");
	else
		rc = 0;

	while(!rc && total_read_bytes < xfer_size) {
		read_bytes = read(sock, remote_data, xfer_size);
		if(read_bytes > 0)
			total_read_bytes += read_bytes;
		else
			rc = read_bytes;
	}
	return rc;
}
/******************************************************************************
End of socket operations
******************************************************************************/


/* poll_completion */
/******************************************************************************
* Function: poll_completion
*
* Input
* res pointer to resources structure
*
* Output
* none
*
* Returns
* 0 on success, 1 on failure
*
* Description
* Poll the completion queue for a single event. This function will continue to
* poll the queue until MAX_POLL_CQ_TIMEOUT milliseconds have passed.
*
******************************************************************************/
static int poll_completion(struct resources *res)
{
	unsigned long start_time_msec = 0, cur_time_msec = 0;
	struct timeval cur_time = {0};
	struct ibv_wc wc = {0};
	int poll_result = 0;
	int rc = 0;

	/* poll the completion for a while before giving up of doing it .. */
	gettimeofday(&cur_time, NULL);
	start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
	do {
		poll_result = ibv_poll_cq(res->cq, 1, &wc);
		gettimeofday(&cur_time, NULL);
		cur_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
	} while ((poll_result == 0) && ((cur_time_msec - start_time_msec) < MAX_POLL_CQ_TIMEOUT));

	if(poll_result < 0) { /* poll CQ failed */
		fprintf(stderr, "poll CQ failed\n");
		rc = 1;
	} else if (poll_result == 0) { /* the CQ is empty */
		fprintf(stderr, "completion wasn't found in the CQ after timeout\n");
		rc = 1;
	} else { /* CQE found */
		fprintf(stdout, "completion was found in CQ with status 0x%x\n", wc.status);

		/* check the completion status (here we don't care about the completion opcode */
		if (wc.status != IBV_WC_SUCCESS) {
			fprintf(stdout, " got bad completion with ibv_wc wr_id: 0x%lx, status:0x%x, opcode: 0x%x, byte_len: 0x%x, local qp number: 0x%x, remote qp number: 0x%x\n", wc.wr_id, wc.status, wc.opcode, wc.byte_len, wc.qp_num, wc.src_qp);
			rc = 1;
		} else {
			fprintf(stdout, " ibv_wc wr_id: 0x%lx, status:0x%x, opcode: 0x%x, byte_len: 0x%x, local qp number: 0x%x, remote qp number: 0x%x\n", wc.wr_id, wc.status, wc.opcode, wc.byte_len, wc.qp_num, wc.src_qp);
		}
	}
	return rc;
}

/******************************************************************************
* Function: post_send
*
* Input
* res pointer to resources structure
* opcode IBV_WR_SEND, IBV_WR_RDMA_READ or IBV_WR_RDMA_WRITE
*
* Output
* none
*
* Returns
* 0 on success, error code on failure
*
* Description
* This function will create and post a send work request
******************************************************************************/
static int post_send(struct resources *res, int opcode)
{
	struct ibv_send_wr sr = {0};
	struct ibv_sge sge = {0};
	struct ibv_send_wr *bad_wr = NULL;
	int rc = 0;

	/* prepare the scatter/gather entry */
	memset(&sge, 0, sizeof(sge));
	sge.addr = (uintptr_t)res->buf;
	sge.length = MSG_SIZE;
	sge.lkey = res->mr->lkey;

	/* prepare the send work request */
	memset(&sr, 0, sizeof(sr));
	sr.next = NULL;
	sr.wr_id = 0;
	sr.sg_list = &sge;
	sr.num_sge = 1;
	sr.opcode = opcode;
	sr.send_flags = IBV_SEND_SIGNALED;

	if(opcode != IBV_WR_SEND) {
		sr.wr.rdma.remote_addr = res->remote_props.addr;
		sr.wr.rdma.rkey = res->remote_props.rkey;
	}

	/* there is a Receive Request in the responder side, so we won't get any into RNR flow */
	rc = ibv_post_send(res->qp, &sr, &bad_wr);
	if (rc) {
		fprintf(stderr, "failed to post SR\n");
	} else {
		switch(opcode) {
		case IBV_WR_SEND:
			fprintf(stdout, "Send Request was posted\n");
			break;
		case IBV_WR_RDMA_READ:
			fprintf(stdout, "RDMA Read Request was posted\n");
			break;
		case IBV_WR_RDMA_WRITE:
			fprintf(stdout, "RDMA Write Request was posted\n");
			break;
		default:
			fprintf(stdout, "Unknown Request was posted\n");
			break;
		}
	}
	return rc;
}
static int post_send_beacon(struct resources *res)
{
	struct ibv_send_wr beacon = {0};
	struct ibv_send_wr *bad_wr = NULL;
	int rc = 0;

	/* prepare the send work request */
	memset(&beacon, 0, sizeof(beacon));
	beacon.wr_id = 0xdeadbeef;
	beacon.opcode = IBV_WR_SEND;
	beacon.send_flags = IBV_SEND_SIGNALED;

	/* there is a Receive Request in the responder side, so we won't get any into RNR flow */
	rc = ibv_post_send(res->qp, &beacon, &bad_wr);
	if (rc) {
		fprintf(stderr, "failed to post SR\n");
	} else {
		fprintf(stdout, "Send Request was posted\n");
	}
	return rc;
}

/******************************************************************************
* Function: post_receive
*
* Input
* res pointer to resources structure
*
* Output
* none
*
* Returns
* 0 on success, error code on failure
*
* Description
*
******************************************************************************/
static int post_receive(struct resources *res)
{
	struct ibv_recv_wr rr = {0};
	struct ibv_sge sge = {0};
	struct ibv_recv_wr *bad_wr = NULL;
	int rc = 0;

	/* prepare the scatter/gather entry */
	memset(&sge, 0, sizeof(sge));
	sge.addr = (uintptr_t)res->buf;
	sge.length = MSG_SIZE;
	sge.lkey = res->mr->lkey;

	/* prepare the receive work request */
	memset(&rr, 0, sizeof(rr));
	rr.next = NULL;
	rr.wr_id = 0;
	rr.sg_list = &sge;
	rr.num_sge = 1;

	/* post the Receive Request to the RQ */
	rc = ibv_post_recv(res->qp, &rr, &bad_wr);
	if (rc)
		fprintf(stderr, "failed to post RR\n");
	else
		fprintf(stdout, "Receive Request was posted\n");

	return rc;
}


/******************************************************************************
* Function: resources_init
*
* Input
* res pointer to resources structure
*
* Output
* res is initialized
*
* Returns
* none
*
* Description
* res is initialized to default values
******************************************************************************/
static void resources_init(struct resources *res)
{
	memset(res, 0, sizeof *res);
	res->sock = -1;
}

/******************************************************************************
* Function: resources_create
*
* Input
* res pointer to resources structure to be filled in
*
* Output
* res filled in with resources
*
* Returns
* 0 on success, 1 on failure
*
* Description
*
* This function creates and allocates all necessary system resources. These
* are stored in res.
*****************************************************************************/
static int resources_create(struct resources *res)
{
	struct ibv_device **dev_list = NULL;
	struct ibv_qp_init_attr qp_init_attr = {0};
	struct ibv_device *ib_dev = NULL;
	size_t size = MSG_SIZE;

	int i = 0;
	int mr_flags = 0;
	int cq_size = 0;
	int num_devices = 0;
	int rc = 0;

	/* if client side */
	if (config.server_name) {
		res->sock = sock_connect(config.server_name, config.tcp_port);
		if (res->sock < 0) {
			fprintf(stderr, "failed to establish TCP connection to server %s, port %d\n", config.server_name, config.tcp_port);
			rc = -1;
			goto resources_create_exit;
		}
	} else {
		fprintf(stdout, "waiting on port %d for TCP connection\n", config.tcp_port);
		res->sock = sock_connect(NULL, config.tcp_port);
		if (res->sock < 0) {
			fprintf(stderr, "failed to establish TCP connection with client on port %d\n", config.tcp_port);
			rc = -1;
			goto resources_create_exit;
		}
	}

	fprintf(stdout, "TCP connection was established\n");
	fprintf(stdout, "searching for IB devices in host\n");

	/* get device names in the system */
	dev_list = ibv_get_device_list(&num_devices);
	if (!dev_list) {
		fprintf(stderr, "failed to get IB devices list\n");
		rc = 1;
		goto resources_create_exit;
	}

	/* if there isn't any IB device in host */
	if (!num_devices) {
		fprintf(stderr, "found %d device(s)\n", num_devices);
		rc = 1;
		goto resources_create_exit;
	}

	fprintf(stdout, "found %d device(s)\n", num_devices);
	/* search for the specific device we want to work with */
	for (i = 0; i < num_devices; i ++) {
		if(!config.dev_name) {
			config.dev_name = strdup(ibv_get_device_name(dev_list[i]));
			fprintf(stdout, "device not specified, using first one found: %s\n", config.dev_name);
		}
		if (!strcmp(ibv_get_device_name(dev_list[i]), config.dev_name)) {
			ib_dev = dev_list[i];
			break;
		}
	}

	/* if the device wasn't found in host */
	if (!ib_dev) {
		fprintf(stderr, "IB device %s wasn't found\n", config.dev_name);
		rc = 1;
		goto resources_create_exit;
	}

	/* get device handle */
	res->ib_ctx = ibv_open_device(ib_dev);
	if (!res->ib_ctx) {
		fprintf(stderr, "failed to open device %s\n", config.dev_name);
		rc = 1;
		goto resources_create_exit;
	}

	/* We are now done with device list, free it */
	ibv_free_device_list(dev_list);
	dev_list = NULL;
	ib_dev = NULL;

	/* query port properties */
	if (ibv_query_port(res->ib_ctx, config.ib_port, &res->port_attr)) {
		fprintf(stderr, "ibv_query_port on port %u failed\n", config.ib_port);
		rc = 1;
		goto resources_create_exit;
	}

	/* allocate Protection Domain */
	res->pd = ibv_alloc_pd(res->ib_ctx);
	if (!res->pd) {
		fprintf(stderr, "ibv_alloc_pd failed\n");
		rc = 1;
		goto resources_create_exit;
	}

	/* each side will send only one WR, so Completion Queue with 1 entry is enough */
	cq_size = 1;
	res->cq = ibv_create_cq(res->ib_ctx, cq_size, NULL, NULL, 0);
	if (!res->cq) {
		fprintf(stderr, "failed to create CQ with %u entries\n", cq_size);
		rc = 1;
		goto resources_create_exit;
	}

	/* allocate the memory buffer that will hold the data */
	res->buf = (char *)calloc(1, size);
	if (!res->buf) {
		fprintf(stderr, "failed to malloc %Zu bytes to memory buffer\n", size);
		rc = 1;
		goto resources_create_exit;
	}

	/* only in the server side put the message in the memory buffer */
	if (!config.server_name) {
		strcpy(res->buf, MSG);
		fprintf(stdout, "going to send the message: '%s'\n", res->buf);
	}

	/* register the memory buffer */
	mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE ;
	res->mr = ibv_reg_mr(res->pd, res->buf, size, mr_flags);
	if (!res->mr) {
		fprintf(stderr, "ibv_reg_mr failed with mr_flags=0x%x\n", mr_flags);
		rc = 1;
		goto resources_create_exit;
	}
	fprintf(stdout, "MR was registered with addr=%p, lkey=0x%x, rkey=0x%x, flags=0x%x\n", res->buf, res->mr->lkey, res->mr->rkey, mr_flags);

	/* create the Queue Pair */
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.send_cq = res->cq;
	qp_init_attr.recv_cq = res->cq;
	qp_init_attr.cap.max_send_wr = 1;
	qp_init_attr.cap.max_recv_wr = 1;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.sq_sig_all = 0;
	res->qp = ibv_create_qp(res->pd, &qp_init_attr);
	if (!res->qp) {
		fprintf(stderr, "failed to create QP\n");
		rc = 1;
		goto resources_create_exit;
	}
	fprintf(stdout, "QP was created, QP number=0x%x\n", res->qp->qp_num);

resources_create_exit:
	if(rc) {
		/* Error encountered, cleanup */
		if(res->qp) {
			ibv_destroy_qp(res->qp);
			res->qp = NULL;
		}

		if(res->mr) {
			ibv_dereg_mr(res->mr);
			res->mr = NULL;
		}

		if(res->buf) {
			free(res->buf);
			res->buf = NULL;
		}

		if(res->cq) {
			ibv_destroy_cq(res->cq);
			res->cq = NULL;
		}

		if(res->pd) {
			ibv_dealloc_pd(res->pd);
			res->pd = NULL;
		}

		if(res->ib_ctx) {
			ibv_close_device(res->ib_ctx);
			res->ib_ctx = NULL;
		}

		if(dev_list) {
			ibv_free_device_list(dev_list);
			dev_list = NULL;
		}

		if (res->sock >= 0) {
			if (close(res->sock))
				fprintf(stderr, "failed to close socket\n");
			res->sock = -1;
		}
	}

	return rc;
}

/******************************************************************************
* Function: modify_qp_to_init
*
* Input
* qp QP to transition
*
* Output
* none
*
* Returns
* 0 on success, ibv_modify_qp failure code on failure
*
* Description
* Transition a QP from the RESET to INIT state
******************************************************************************/
static int modify_qp_to_init(struct ibv_qp *qp)
{
	struct ibv_qp_attr attr = {0};
	enum ibv_qp_attr_mask mask;
	int rc = 0;

	memset(&attr, 0, sizeof(attr));

	attr.qp_state = IBV_QPS_INIT;
	attr.pkey_index = 0;
	attr.port_num = config.ib_port;
	attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
	mask = IBV_QP_STATE | IBV_QP_PORT | IBV_QP_PKEY_INDEX | IBV_QP_ACCESS_FLAGS;

	rc = ibv_modify_qp(qp, &attr, mask);
	if (rc)
		fprintf(stderr, "failed to modify QP state to INIT\n");
	return rc;
}

/******************************************************************************
* Function: modify_qp_to_rtr
*
* Input
* qp QP to transition
* remote_qpn remote QP number
* dlid destination LID
* dgid destination GID (mandatory for RoCEE)
*
* Output
* none
*
* Returns
* 0 on success, ibv_modify_qp failure code on failure
*
* Description
* Transition a QP from the INIT to RTR state, using the specified QP number
******************************************************************************/
static int modify_qp_to_rtr(struct ibv_qp *qp, uint32_t remote_qpn, uint16_t dlid, uint8_t *dgid)
{
	struct ibv_qp_attr attr = {0};
	enum ibv_qp_attr_mask mask;
	int rc = 0;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTR;
	attr.path_mtu = IBV_MTU_256;
	attr.dest_qp_num = remote_qpn;
	attr.rq_psn = 0;
	attr.max_dest_rd_atomic = 1;
	attr.min_rnr_timer = 0x12;

	attr.ah_attr.is_global = 0;
	attr.ah_attr.dlid = dlid;
	attr.ah_attr.sl = 0;
	attr.ah_attr.src_path_bits = 0;
	attr.ah_attr.port_num = config.ib_port;

	if (config.gid_idx >= 0) {
		attr.ah_attr.is_global = 1;
		attr.ah_attr.port_num = 1;
		memcpy(&attr.ah_attr.grh.dgid, dgid, 16);
		attr.ah_attr.grh.flow_label = 0;
		attr.ah_attr.grh.hop_limit = 1;
		attr.ah_attr.grh.sgid_index = config.gid_idx;
		attr.ah_attr.grh.traffic_class = 0;
	}

	mask = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
	rc = ibv_modify_qp(qp, &attr, mask);
	if (rc)
		fprintf(stderr, "failed to modify QP state to RTR\n");
	return rc;
}

static int modify_qp_to_error(struct ibv_qp *qp)
{
	struct ibv_qp_attr qpa;
	memset(&qpa, 0, sizeof(qpa));
	qpa.qp_state = IBV_QPS_ERR;
	if (ibv_modify_qp(qp, &qpa, IBV_QP_STATE)) {
		fprintf(stderr, " failed to transition to error qp number:0x%x\n", qp->qp_num);
		return -1;
	}
	fprintf(stdout, " switch to error qp number:0x%x\n", qp->qp_num);
	return 0;
}

static int query_qp_state(struct ibv_qp *qp)
{
	struct ibv_qp_attr qpa;
	struct ibv_qp_init_attr qpia;

	int r = ibv_query_qp(qp, &qpa, IBV_QP_STATE, &qpia);
	if (r) {
		fprintf(stderr, " failed to query qp state, qp number:0x%x\n", qp->qp_num);
		return -1;
	}
	fprintf(stdout, " qp number: 0x%x, state: 0x%x\n", qp->qp_num, qpa.qp_state);
	return qpa.qp_state;
}

static int get_remote_qpn(struct ibv_qp *qp)
{
	struct ibv_qp_attr qpa;
	struct ibv_qp_init_attr qpia;

	int r = ibv_query_qp(qp, &qpa, IBV_QP_DEST_QPN, &qpia);
	if (r) {
		fprintf(stderr, " failed to query remote qp number, local qp number:0x%x\n", qp->qp_num);
		return -1;
	}
	fprintf(stdout, " local qp number: 0x%x, remote qp number: 0x%x\n", qp->qp_num, qpa.dest_qp_num);
	return qpa.dest_qp_num;
}


/******************************************************************************
* Function: modify_qp_to_rts
*
* Input
* qp QP to transition
*
* Output
* none
*
* Returns
* 0 on success, ibv_modify_qp failure code on failure
*
* Description
* Transition a QP from the RTR to RTS state
******************************************************************************/
static int modify_qp_to_rts(struct ibv_qp *qp)
{
	struct ibv_qp_attr attr = {0};
	enum ibv_qp_attr_mask mask;
	int rc = 0;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.timeout = 0x12;
	attr.retry_cnt = 6;
	attr.rnr_retry = 0;
	attr.sq_psn = 0;
	attr.max_rd_atomic = 1;
	mask = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
	rc = ibv_modify_qp(qp, &attr, mask);
	if (rc)
		fprintf(stderr, "failed to modify QP state to RTS\n");
	return rc;
}

/******************************************************************************
* Function: connect_qp
*
* Input
* res pointer to resources structure
*
* Output
* none
*
* Returns
* 0 on success, error code on failure
*
* Description
* Connect the QP. Transition the server side to RTR, sender side to RTS
******************************************************************************/
static int connect_qp(struct resources *res)
{
	struct cm_con_data_t local_con_data = {0};
	struct cm_con_data_t remote_con_data = {0};
	struct cm_con_data_t tmp_con_data = {0};
	int rc = 0;
	char temp_char;
	union ibv_gid my_gid = {0};

	if (config.gid_idx >= 0) {
		rc = ibv_query_gid(res->ib_ctx, config.ib_port, config.gid_idx, &my_gid);
		if (rc) {
			fprintf(stderr, "could not get gid for port %d, index %d\n", config.ib_port, config.gid_idx);
			return rc;
		}
	} else
		memset(&my_gid, 0, sizeof my_gid);

	/* exchange using TCP sockets info required to connect QPs */
	local_con_data.addr = htonll((uintptr_t)res->buf);
	local_con_data.rkey = htonl(res->mr->rkey);
	local_con_data.qp_num = htonl(res->qp->qp_num);
	local_con_data.lid = htons(res->port_attr.lid);
	memcpy(local_con_data.gid, &my_gid, 16);
	fprintf(stdout, "\nLocal LID = 0x%x\n", res->port_attr.lid);
	if (sock_sync_data(res->sock, sizeof(struct cm_con_data_t), (char *) &local_con_data, (char *) &tmp_con_data) < 0) {
		fprintf(stderr, "failed to exchange connection data between sides\n");
		rc = 1;
		goto connect_qp_exit;
	}
	remote_con_data.addr = ntohll(tmp_con_data.addr);
	remote_con_data.rkey = ntohl(tmp_con_data.rkey);
	remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
	remote_con_data.lid = ntohs(tmp_con_data.lid);
	memcpy(remote_con_data.gid, tmp_con_data.gid, 16);

	/* save the remote side attributes, we will need it for the post SR */
	res->remote_props = remote_con_data;
	fprintf(stdout, "Remote address = 0x%"PRIx64"\n", remote_con_data.addr);
	fprintf(stdout, "Remote rkey = 0x%x\n", remote_con_data.rkey);
	fprintf(stdout, "Local QP number = 0x%x\n", res->qp->qp_num);
	fprintf(stdout, "Remote QP number = 0x%x\n", remote_con_data.qp_num);
	fprintf(stdout, "Remote LID = 0x%x\n", remote_con_data.lid);

	if (config.gid_idx >= 0) {
		uint8_t *p = remote_con_data.gid;
		fprintf(stdout, "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
				p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
	}

	/* modify the QP to init */
	rc = modify_qp_to_init(res->qp);
	if (rc) {
		fprintf(stderr, "change QP state to INIT failed\n");
		goto connect_qp_exit;
	}

	/* let the client post RR to be prepared for incoming messages */
	if (config.server_name) {
		rc = post_receive(res);
		if (rc) {
			fprintf(stderr, "failed to post RR\n");
			goto connect_qp_exit;
		}
	}

	/* modify the QP to RTR */
	rc = modify_qp_to_rtr(res->qp, remote_con_data.qp_num, remote_con_data.lid, remote_con_data.gid);
	if (rc) {
		fprintf(stderr, "failed to modify QP state to RTR\n");
		goto connect_qp_exit;
	}
	rc = modify_qp_to_rts(res->qp);
	if (rc) {
		fprintf(stderr, "failed to modify QP state to RTS\n");
		goto connect_qp_exit;
	}
	fprintf(stdout, "QP state was change to RTS\n");
	/* sync to make sure that both sides are in states that they can connect to prevent packet loose */
	if (sock_sync_data(res->sock, 1, "Q", &temp_char)) { /* just send a dummy char back and forth */
		fprintf(stderr, "sync error after QPs are were moved to RTS\n");
		rc = 1;
	}
connect_qp_exit:
	return rc;
}

/******************************************************************************
* Function: resources_destroy
*
* Input
* res pointer to resources structure
*
* Output
* none
*
* Returns
* 0 on success, 1 on failure
*
* Description
* Cleanup and deallocate all resources used
******************************************************************************/
static int resources_destroy(struct resources *res)
{
	int rc = 0;
	if (res->qp)
		if (ibv_destroy_qp(res->qp)) {
			fprintf(stderr, "failed to destroy QP\n");
			rc = 1;
		}

	if (res->mr)
		if (ibv_dereg_mr(res->mr)) {
			fprintf(stderr, "failed to deregister MR\n");
			rc = 1;
		}

	if (res->buf)
		free(res->buf);

	if (res->cq)
		if (ibv_destroy_cq(res->cq)) {
			fprintf(stderr, "failed to destroy CQ\n");
			rc = 1;
		}

	if (res->pd)
		if (ibv_dealloc_pd(res->pd)) {
			fprintf(stderr, "failed to deallocate PD\n");
			rc = 1;
		}

	if (res->ib_ctx)
		if (ibv_close_device(res->ib_ctx)) {
			fprintf(stderr, "failed to close device context\n");
			rc = 1;
		}

	if (res->sock >= 0)
		if (close(res->sock)) {
			fprintf(stderr, "failed to close socket\n");
			rc = 1;
		}

return rc;
}

/******************************************************************************
* Function: print_config
*
* Input
* none
*
* Output
* none
*
* Returns
* none
*
* Description
* Print out config information
******************************************************************************/
static void print_config(void)
{
	fprintf(stdout, " ------------------------------------------------\n");
	fprintf(stdout, " Device name : \"%s\"\n", config.dev_name);
	fprintf(stdout, " IB port : %u\n", config.ib_port);

	if (config.server_name)
		fprintf(stdout, " IP : %s\n", config.server_name);

	fprintf(stdout, " TCP port : %u\n", config.tcp_port);

	if (config.gid_idx >= 0)
		fprintf(stdout, " GID index : %u\n", config.gid_idx);

	fprintf(stdout, " ------------------------------------------------\n\n");
}

/******************************************************************************
* Function: usage
*
* Input
* argv0 command line arguments
*
* Output
* none
*
* Returns
* none
*
* Description
* print a description of command line syntax
******************************************************************************/
static void usage(const char *argv0)
{
	fprintf(stdout, "Usage:\n");
	fprintf(stdout, " %s start a server and wait for connection\n", argv0);
	fprintf(stdout, " %s <host> connect to server at <host>\n", argv0);
	fprintf(stdout, "\n");
	fprintf(stdout, "Options:\n");
	fprintf(stdout, " -p, --port <port> listen on/connect to port <port> (default 19875)\n");
	fprintf(stdout, " -d, --ib-dev <dev> use IB device <dev> (default first device found)\n");
	fprintf(stdout, " -i, --ib-port <port> use port <port> of IB device (default 1)\n");
	fprintf(stdout, " -g, --gid_idx <git index> gid index to be used in GRH (default not used)\n");
}

/******************************************************************************
* Function: main
*
* Input
* argc number of items in argv
* argv command line parameters
*
* Output
* none
*
* Returns
* 0 on success, 1 on failure
*
* Description
* Main program code
******************************************************************************/
int main(int argc, char *argv[])
{
	struct resources res = {0};
	int rc = 1;

	/* parse the command line parameters */
	while (1) {
		int c = 0;
		static struct option long_options[] = {
			{.name = "port", .has_arg = 1, .val = 'p' },
			{.name = "ib-dev", .has_arg = 1, .val = 'd' },
			{.name = "ib-port", .has_arg = 1, .val = 'i' },
			{.name = "gid-idx", .has_arg = 1, .val = 'g' },
			{.name = NULL, .has_arg = 0, .val = '\0'}
		};

		c = getopt_long(argc, argv, "p:d:i:g:", long_options, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'p':
			config.tcp_port = strtoul(optarg, NULL, 0);
			break;
		case 'd':
			config.dev_name = strdup(optarg);
			break;
		case 'i':
			config.ib_port = strtoul(optarg, NULL, 0);
			if (config.ib_port < 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'g':
			config.gid_idx = strtoul(optarg, NULL, 0);
			if (config.gid_idx < 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	/* parse the last parameter (if exists) as the server name */
	if (optind == argc - 1) {
		config.server_name = argv[optind];
	} else if (optind < argc) {
		usage(argv[0]);
		return 1;
	}

	/* print the used parameters for info*/
	print_config();

	/* init all of the resources, so cleanup will be easy */
	resources_init(&res);

	/* create resources before using them */
	if (resources_create(&res)) {
		fprintf(stderr, "failed to create resources\n");
		goto main_exit;
	}

	fprintf(stdout, "*********begin connect qp***********\n");
	/* connect the QPs */
	if (connect_qp(&res)) {
		fprintf(stderr, "failed to connect QPs\n");
		goto main_exit;
	}
	query_qp_state(res.qp);
	fprintf(stdout, "*********qp connected***********\n");

	/* let the server post the sr */
	fprintf(stdout, "**********force qp into error state ************\n");
	if (!config.server_name) {
	if (modify_qp_to_error(res.qp)) {
		fprintf(stderr, "failed to transition to error\n");
		goto main_exit;
	}
	}
	if (!config.server_name) {
		fprintf(stdout, "**********server post beacon************\n");
		if (post_send_beacon(&res)) {
			fprintf(stderr, "failed to post sr\n");
			goto main_exit;
		}
	}

//	query_qp_state(res.qp);

//	get_remote_qpn(res.qp);
	/* in both sides we expect to get a completion */
	if (poll_completion(&res)) {
		fprintf(stderr, "poll completion failed\n");
		goto main_exit;
	}
	fprintf(stdout, "***********all finish the poll completion***********\n");

	rc = 0;
main_exit:
	if (resources_destroy(&res)) {
		fprintf(stderr, "failed to destroy resources\n");
		rc = 1;
	}

	if(config.dev_name)
		free((char *) config.dev_name);

	fprintf(stdout, "\ntest result is %d\n", rc);
	return rc;
}
