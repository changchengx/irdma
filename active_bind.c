#include <stdio.h>

#include <rdma/rdma_cma.h>
int main(void)
{
	const char* client_active_bind = "192.168.30.2";
	const char* server_passive_bind = "192.168.30.4";
	const char* service = "8976";

	struct rdma_addrinfo *client_local_bind_rai = NULL;
	struct rdma_addrinfo *target_rai = NULL;
	struct rdma_addrinfo hints;
	struct rdma_cm_id *id;

	int ret = 0;

	memset(&hints, 0, sizeof (hints));
	hints.ai_port_space = RDMA_PS_TCP;

	hints.ai_flags = RAI_PASSIVE;
	ret = rdma_getaddrinfo(client_active_bind, NULL, &hints, &client_local_bind_rai);

	hints.ai_src_addr = client_local_bind_rai->ai_src_addr;
	hints.ai_src_len  = client_local_bind_rai->ai_src_len;
	hints.ai_flags = 0;

	ret = rdma_getaddrinfo(server_passive_bind, service, &hints, &target_rai);

    rdma_create_id(NULL, &id, NULL, RDMA_PS_TCP);

#if 0
	ret = rdma_bind_addr(id, target_rai->ai_src_addr);
    printf("%s\n", ibv_get_device_name(id->verbs->device));
#endif

  	ret = rdma_resolve_addr(id, target_rai->ai_src_addr, target_rai->ai_dst_addr, 2000);
	printf("%d: %d\n", __LINE__, ret);
	printf("%s\n", ibv_get_device_name(id->verbs->device));
	return 0;
}


#if 0
=====================================================================================================================
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rdma/rdma_cma.h>

int set_sockaddr(const char* ip_str, uint16_t port, struct sockaddr* saddr)
{
    struct sockaddr_in* sa_in = (struct sockaddr_in*)saddr;
    if (inet_pton(AF_INET, ip_str, &sa_in->sin_addr) == 1) {
        sa_in->sin_family = AF_INET;
        sa_in->sin_port   = htons(port);
        return 0;
    }

    struct sockaddr_in6* sa_in6 = (struct sockaddr_in6*)saddr;
    if (inet_pton(AF_INET6, ip_str, &sa_in6->sin6_addr) == 1) {
        sa_in6->sin6_family = AF_INET6;
        sa_in6->sin6_port   = htons(port);
        return 0;
    }

    return 0;
}

int main(void)
{
	const char* client_active_bind = "192.168.30.160";
	const char* server_passive_bind = "192.168.30.162";
	struct rdma_cm_id *id;
    struct sockaddr_storage dst_addr, src_addr;

	set_sockaddr(client_active_bind, 0, (struct sockaddr*)&src_addr);
	set_sockaddr(server_passive_bind, 8976, (struct sockaddr*)&dst_addr);

    rdma_create_id(NULL, &id, NULL, RDMA_PS_TCP);
	int ret = rdma_resolve_addr(id, (struct sockaddr*)(&src_addr), (struct sockaddr*)(&dst_addr), 2000);
    printf("%d\n", ret);
	printf("%s\n", ibv_get_device_name(id->verbs->device));

	return 0;
}
#endif
