/*
 *
 * Copyright (C) 2005-2007 Takahiro Hirofuchi
 */

#include <ws2tcpip.h>
#include <mstcpip.h>

#include "usbip_common.h"
#include "usbip_network.h"
#include "dbgcode.h"

#include "ikcp.h"
#include "ikcp_util.h"

#define MTU_SIZE 1500

int usbip_port = 3240;
char *usbip_port_string = "3240";

static SOCKET g_local_socket[2] = { INVALID_SOCKET, INVALID_SOCKET }; // 0: usbip, 1: KCP
static SOCKET g_kcp_socket = INVALID_SOCKET;
static struct sockaddr_in g_server_addr;
static ikcpcb *g_kcp = NULL;
static char g_usbip_buffer[MTU_SIZE];
static char g_kcp_buffer[MTU_SIZE];

void usbip_setup_port_number(char* arg)
{
	char *end;
	unsigned long int port = strtoul(arg, &end, 10);

	if (end == arg) {
		dbg("port: could not parse '%s' as a decimal integer", arg);
		return;
	}

	if (*end != '\0') {
		dbg("port: garbage at end of '%s'", arg);
		return;
	}

	if (port > UINT16_MAX) {
		dbg("port: %s too high (max=%d)",
			arg, UINT16_MAX);
		return;
	}

	usbip_port = port;
	usbip_port_string = arg;
	info("using port %d (\"%s\")", usbip_port, usbip_port_string);
}

void usbip_net_pack_uint32_t(int pack, uint32_t *num)
{
	uint32_t i;

	if (pack)
		i = htonl(*num);
	else
		i = ntohl(*num);

	*num = i;
}

void usbip_net_pack_uint16_t(int pack, uint16_t *num)
{
	uint16_t i;

	if (pack)
		i = htons(*num);
	else
		i = ntohs(*num);

	*num = i;
}

void usbip_net_pack_usb_device(int pack, struct usbip_usb_device *udev)
{
	usbip_net_pack_uint32_t(pack, &udev->busnum);
	usbip_net_pack_uint32_t(pack, &udev->devnum);
	usbip_net_pack_uint32_t(pack, &udev->speed);

	usbip_net_pack_uint16_t(pack, &udev->idVendor);
	usbip_net_pack_uint16_t(pack, &udev->idProduct);
	usbip_net_pack_uint16_t(pack, &udev->bcdDevice);
}

void usbip_net_pack_usb_interface(int pack, struct usbip_usb_interface *udev)
{
	UNREFERENCED_PARAMETER(pack);
	UNREFERENCED_PARAMETER(udev);
	/* uint8_t members need nothing */
}

static int usbip_net_xmit(SOCKET sockfd, void *buff, size_t bufflen, int sending)
{
	int total = 0;

	if (!bufflen)
		return 0;

	do {
		int nbytes;

		if (sending)
			nbytes = send(sockfd, buff, (int)bufflen, 0);
		else
			nbytes = recv(sockfd, buff, (int)bufflen, 0);

		if (nbytes <= 0)
			return -1;

		buff	= (void *) ((intptr_t) buff + nbytes);
		bufflen	-= nbytes;
		total	+= nbytes;
	} while (bufflen > 0);

	return total;
}

int usbip_net_recv(SOCKET sockfd, void *buff, size_t bufflen)
{
	return usbip_net_xmit(sockfd, buff, bufflen, 0);
}

int usbip_net_send(SOCKET sockfd, void *buff, size_t bufflen)
{
	return usbip_net_xmit(sockfd, buff, bufflen, 1);
}

int usbip_net_send_op_common(SOCKET sockfd, uint32_t code, uint32_t status)
{
	struct op_common op_common;
	int rc;

	memset(&op_common, 0, sizeof(op_common));

	op_common.version = USBIP_VERSION;
	op_common.code    = code;
	op_common.status  = status;

	PACK_OP_COMMON(1, &op_common);

	rc = usbip_net_send(sockfd, &op_common, sizeof(op_common));
	if (rc < 0) {
		dbg("usbip_net_send failed: %d", rc);
		return -1;
	}

	return 0;
}

int usbip_net_recv_op_common(SOCKET sockfd, uint16_t *code, int *pstatus)
{
	struct op_common op_common;
	int rc;

	memset(&op_common, 0, sizeof(op_common));

	rc = usbip_net_recv(sockfd, &op_common, sizeof(op_common));
	if (rc < 0) {
		dbg("usbip_net_recv failed: %d", rc);
		return ERR_NETWORK;
	}

	PACK_OP_COMMON(0, &op_common);

	if (op_common.version != USBIP_VERSION) {
		dbg("version mismatch: %d != %d", op_common.version, USBIP_VERSION);
		return ERR_VERSION;
	}

	switch (*code) {
	case OP_UNSPEC:
		break;
	default:
		if (op_common.code != *code) {
			dbg("unexpected pdu %#0x for %#0x", op_common.code, *code);
			return ERR_PROTOCOL;
		}
	}

	*pstatus = op_common.status;

	if (op_common.status != ST_OK) {
		dbg("request failed: status: %s", dbg_opcode_status(op_common.status));
		return ERR_STATUS;
	}

	*code = op_common.code;
	return 0;
}

int usbip_net_set_reuseaddr(SOCKET sockfd)
{
	const int val = 1;
	int ret;

	ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&val, sizeof(val));
	if (ret < 0)
		dbg("setsockopt: SO_REUSEADDR");

	return ret;
}

int usbip_net_set_nodelay(SOCKET sockfd)
{
	const int val = 1;
	int ret;

	ret = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void*)&val, sizeof(val));
	if (ret < 0)
		dbg("setsockopt: TCP_NODELAY");

	return ret;
}

unsigned
get_keepalive_timeout(void)
{
	char	env_timeout[32];
	unsigned	timeout;
	size_t	reqsize;

	if (getenv_s(&reqsize, env_timeout, 32, "KEEPALIVE_TIMEOUT") != 0)
		return 0;

	if (sscanf_s(env_timeout, "%u", &timeout) == 1)
		return timeout;
	return 0;
}

int usbip_net_set_keepalive(SOCKET sockfd)
{
	unsigned	timeout;

	timeout = get_keepalive_timeout();
	if (timeout > 0) {
		struct tcp_keepalive	keepalive;
		DWORD	outlen;
		int	ret;

		/* windows tries 10 times every keepaliveinterval */
		keepalive.onoff = 1;
		keepalive.keepalivetime = timeout * 1000 / 2;
		keepalive.keepaliveinterval = timeout * 1000 / 10 / 2;

		ret = WSAIoctl(sockfd, SIO_KEEPALIVE_VALS, &keepalive, sizeof(keepalive), NULL, 0, &outlen, NULL, NULL);
		if (ret != 0) {
			dbg("failed to set KEEPALIVE via SIO_KEEPALIVE_VALS: 0x%lx", GetLastError());
			return -1;
		}
		return 0;
	}
	else {
		DWORD	val = 1;
		int	ret;

		ret = setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&val, sizeof(val));
		if (ret < 0) {
			dbg("failed to set KEEPALIVE via setsockopt: 0x%lx", GetLastError());
		}
		return ret;
	}
}

int usbip_net_set_v6only(SOCKET sockfd)
{
	const int val = 1;
	int ret;

	ret = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&val, sizeof(val));
	if (ret < 0)
		dbg("setsockopt: IPV6_V6ONLY");

	return ret;
}

/*
 * IPv6 Ready
 */
SOCKET usbip_net_tcp_connect(const char *hostname, const char *port)
{
	struct addrinfo hints, *res, *rp;
	SOCKET sockfd = INVALID_SOCKET;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	/* get all possible addresses */
	ret = getaddrinfo(hostname, port, &hints, &res);
	if (ret < 0) {
		dbg("getaddrinfo: %s port %s: %s", hostname, port,
		    gai_strerror(ret));
		return INVALID_SOCKET;
	}

	/* try the addresses */
	for (rp = res; rp; rp = rp->ai_next) {
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sockfd == INVALID_SOCKET)
			continue;

		/* should set TCP_NODELAY for usbip */
		usbip_net_set_nodelay(sockfd);
		/* TODO: write code for heartbeat */
		// do not use
		// usbip_net_set_keepalive(sockfd);

		if (connect(sockfd, rp->ai_addr, (int)rp->ai_addrlen) == 0)
			break;

		closesocket(sockfd);
	}

	freeaddrinfo(res);

	if (!rp)
		return INVALID_SOCKET;

	return sockfd;
}

static int __stream_socketpair(struct addrinfo *addr_info, SOCKET sock[2]) {
	SOCKET listener, client, server;
	int opt = 1;

	listener = server = client = INVALID_SOCKET;
	listener = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);
	if (INVALID_SOCKET == listener)
		goto fail;

	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

	if (SOCKET_ERROR == bind(listener, addr_info->ai_addr, (int)addr_info->ai_addrlen))
		goto fail;

	if (SOCKET_ERROR == getsockname(listener, addr_info->ai_addr, (int *)&addr_info->ai_addrlen))
		goto fail;

	if (SOCKET_ERROR == listen(listener, 5))
		goto fail;

	client = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);

	if (INVALID_SOCKET == client)
		goto fail;

	if (SOCKET_ERROR == connect(client, addr_info->ai_addr, (int)addr_info->ai_addrlen))
		goto fail;

	server = accept(listener, 0, 0);

	if (INVALID_SOCKET == server)
		goto fail;

	closesocket(listener);

	setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (const char *)&opt, sizeof(opt));
	setsockopt(server, IPPROTO_TCP, TCP_NODELAY, (const char *)&opt, sizeof(opt));

	sock[0] = client;
	sock[1] = server;

	return 0;
fail:
	if (INVALID_SOCKET != listener)
		closesocket(listener);
	if (INVALID_SOCKET != client)
		closesocket(client);
	return -1;
}

static int __dgram_socketpair(struct addrinfo *addr_info, SOCKET sock[2])
{
	SOCKET client, server;
	struct addrinfo addr, *result = NULL;
	const char *address;
	int opt = 1;

	server = client = INVALID_SOCKET;

	server = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);
	if (INVALID_SOCKET == server)
		goto fail;

	setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

	if (SOCKET_ERROR == bind(server, addr_info->ai_addr, (int)addr_info->ai_addrlen))
		goto fail;

	if (SOCKET_ERROR == getsockname(server, addr_info->ai_addr, (int *)&addr_info->ai_addrlen))
		goto fail;

	client = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);
	if (INVALID_SOCKET == client)
		goto fail;

	memset(&addr, 0, sizeof(addr));
	addr.ai_family = addr_info->ai_family;
	addr.ai_socktype = addr_info->ai_socktype;
	addr.ai_protocol = addr_info->ai_protocol;

	if (AF_INET6 == addr.ai_family)
		address = "0:0:0:0:0:0:0:1";
	else
		address = "127.0.0.1";

	if (getaddrinfo(address, "0", &addr, &result))
		goto fail;

	setsockopt(client, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
	if (SOCKET_ERROR == bind(client, result->ai_addr, (int)result->ai_addrlen))
		goto fail;

	if (SOCKET_ERROR == getsockname(client, result->ai_addr, (int *)&result->ai_addrlen))
		goto fail;

	if (SOCKET_ERROR == connect(server, result->ai_addr, (int)result->ai_addrlen))
		goto fail;

	if (SOCKET_ERROR == connect(client, addr_info->ai_addr, (int)addr_info->ai_addrlen))
		goto fail;

	freeaddrinfo(result);
	sock[0] = client;
	sock[1] = server;
	return 0;

fail:
	if (INVALID_SOCKET != client)
		closesocket(client);
	if (INVALID_SOCKET != server)
		closesocket(server);
	if (result)
		freeaddrinfo(result);
	return -1;
}

int socketpair(int family, int type, int protocol, SOCKET recv[2]) {
	const char *address;
	struct addrinfo addr_info, *p_addrinfo;
	int result = -1;

	memset(&addr_info, 0, sizeof(addr_info));
	addr_info.ai_family = family;
	addr_info.ai_socktype = type;
	addr_info.ai_protocol = protocol;
	if (AF_INET6 == family)
		address = "0:0:0:0:0:0:0:1";
	else
		address = "127.0.0.1";

	if (0 == getaddrinfo(address, "0", &addr_info, &p_addrinfo)) {
		if (SOCK_STREAM == type)
			result = __stream_socketpair(p_addrinfo, recv);   // use for tcp
		else if (SOCK_DGRAM == type)
			result = __dgram_socketpair(p_addrinfo, recv);    // use for udp
		freeaddrinfo(p_addrinfo);
	}
	return result;
}

static int udp_output(const char *buf, int len, ikcpcb *kcp, void *user)
{
	sendto(g_kcp_socket, buf, len, 0, (struct sockaddr *)&(g_server_addr), sizeof(g_server_addr));
	return 0;
}

VOID
ReaderCallBack(DWORD errcode, DWORD nread, LPOVERLAPPED lpOverlapped) {
	if (errcode != 0) {
		err("read fail!");
	}
	else {
		ikcp_send(g_kcp, g_usbip_buffer, nread);
	}
}

VOID
WriterCallBack(DWORD errcode, DWORD nread, LPOVERLAPPED lpOverlapped) {
	if (errcode != 0) {
		err("write fail!");
	}
}

DWORD WINAPI
ProxyThread(LPVOID lpThreadParameter) {
	int addr_len = sizeof(g_server_addr);
	HANDLE local_socket = (HANDLE)g_local_socket[1];

	OVERLAPPED ov_reader;
	OVERLAPPED ov_writer;
	memset(&ov_reader, 0, sizeof(OVERLAPPED));
	memset(&ov_writer, 0, sizeof(OVERLAPPED));

	while (1) {
		SleepEx(1, TRUE);
		ikcp_update(g_kcp, iclock()); // kcp will send udp when update
		if (!ReadFileEx((HANDLE)local_socket, g_usbip_buffer, MTU_SIZE, &ov_reader, ReaderCallBack)) {
			err("read file error %d", (int)GetLastError());
		}


		/* read from udp, then update kcp */
		while (1) {
			int ret = recvfrom(g_kcp_socket, g_kcp_buffer, MTU_SIZE, 0, (struct sockaddr *)&g_server_addr, &addr_len);
			if (ret < 0)
				break;
			ikcp_input(g_kcp, g_kcp_buffer, ret);
		}
		/* get packet from kcp */
		while (1) {
			int ret = ikcp_recv(g_kcp, g_kcp_buffer, MTU_SIZE);
			if (ret < 0)
				break;
			if (!WriteFileEx((HANDLE)local_socket, g_kcp_buffer, ret, &ov_writer, WriterCallBack)) {
				err("write file error %d", (int)GetLastError());
			}
		}

	}
	return 0;
}

SOCKET usbip_net_kcp_connect(const char *hostname, const char *port) {
	/* UDP connect create */
	g_kcp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (g_kcp_socket == INVALID_SOCKET)
		return INVALID_SOCKET;

	/* local client port */
	struct sockaddr_in client_addr;
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = htons(0); // any free port
	client_addr.sin_addr.S_un.S_addr = INADDR_ANY;

	if (bind(g_kcp_socket, (struct sockaddr *)&client_addr, sizeof(client_addr)) == SOCKET_ERROR) {
		err("bind error!");
		goto fail;
	}


	u_long mode = 1;  // 1 to enable non-blocking socket
	ioctlsocket(g_kcp_socket, FIONBIO, &mode);

	g_server_addr.sin_family = AF_INET;
	g_server_addr.sin_port = htons(usbip_port);
	if (inet_pton(AF_INET, hostname, &g_server_addr.sin_addr.s_addr) != 1) {
		err("invalid hostname");
		goto fail;
	}


	/* KCP init */
	g_kcp = ikcp_create(1, (void *)1);
	g_kcp->output = udp_output;

	ikcp_wndsize(g_kcp, 128, 128);

	ikcp_nodelay(g_kcp, 2, 10, 2, 1); 	// set fast mode
	g_kcp->rx_minrto = 10;
	g_kcp->fastresend = 1;

	ikcp_setmtu(g_kcp, 1500);

	/* get local socket pair */
	if (socketpair(AF_INET, SOCK_STREAM, 0, g_local_socket) < 0) {
		err("failed to get local socketpair");
		goto fail;
	}

	/* start KCP thread */
	DWORD thread_id;
	HANDLE thread_handle = CreateThread(
		NULL,                   // default security attributes
		0,                      // use default stack size
		ProxyThread,            // thread function name
		NULL,                   // argument to thread function
		0,                      // use default creation flags
		&thread_id);            // returns the thread identifier

	if (thread_handle == NULL) {
		err("can not create new thread");
		goto fail;
	}


	return g_local_socket[0];

fail:
	closesocket(g_kcp_socket);
	return INVALID_SOCKET;
}