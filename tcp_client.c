#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/socket.h>



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Peter Moroz");

#define PORT 10100
#define MSG_LENGTH 64

struct socket* conn_sock = NULL;


char commands[][5] = { "HELO", "STAT", "SYNC", "QUIT" };


u32 make_addr(unsigned char* ip)
{
	u32 addr = 0;
	int i = 0;
	
	for (; ; i++)
	{
		addr += ip[i];
		if (i == 3)
			break;
		addr <<= 8;
	}
	
	return addr;
}

int tcp_send(struct socket* sock, const char* buffer, size_t length, unsigned long flags)
{
	struct msghdr msg;
	struct kvec vec;
	int len, written = 0, left = length;
	mm_segment_t mmseg;
	
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = flags;
	
	mmseg = get_fs();
	set_fs(KERNEL_DS);
	
repeat_send:
	vec.iov_len = left;
	vec.iov_base = (char *)buffer + written;
	
	len = kernel_sendmsg(sock, &msg, &vec, left, left);
	if ((len == -ERESTARTSYS) || (!(flags & MSG_DONTWAIT) && (len == -EAGAIN)))
		goto repeat_send;
		
	if (len > 0)
	{
		written += len;
		left -= len;
		if (left)
			goto repeat_send;
	}
	
	set_fs(mmseg);
	return written ? written : len;
}

int tcp_receive(struct socket* sock, char* buffer, size_t buflen, unsigned long flags)
{
	struct msghdr msg;
	struct kvec vec;
	int len;
	
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = flags;
	
	vec.iov_len = buflen;
	vec.iov_base = buffer;
	
repeat_recv:
	len = kernel_recvmsg(sock, &msg, &vec, buflen, buflen, flags);
	
	if (len == -EAGAIN || len == -ERESTARTSYS)
		goto repeat_recv;
		
	return len;
}


int tcp_client_connect(void)
{
	struct sockaddr_in saddr;
	
	unsigned char srv_ip[4] = { 192, 168, 171, 103 };
	char request[MSG_LENGTH];
	char response[MSG_LENGTH];
	
	DECLARE_WAIT_QUEUE_HEAD(recv_wait);
	
	int ret;
	int len;
	int i;
	
	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &conn_sock);
	if (ret < 0)
	{
		pr_err("TCP client - sock_create() failed, returned %d\n", ret);
		goto exit_connect;
	}
	
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(PORT);
	saddr.sin_addr.s_addr = htonl(make_addr(srv_ip));
	
	ret = conn_sock->ops->connect(conn_sock, (struct sockaddr*)&saddr, sizeof(saddr), O_RDWR);
	if (ret < 0 && (ret != -EINPROGRESS))
	{
		pr_err("TCP client - connect() failed, returned %d\n", ret);
		goto exit_connect;
	}
	
	for (i = 0; i < 4; i++)
	{
		strcpy(request, commands[i]);
		tcp_send(conn_sock, request, strlen(request), MSG_DONTWAIT);
		wait_event_timeout(recv_wait, !skb_queue_empty(&conn_sock->sk->sk_receive_queue), 5 * HZ);
		if (!skb_queue_empty(&conn_sock->sk->sk_receive_queue))
		{
			len = tcp_receive(conn_sock, response, sizeof(response), MSG_DONTWAIT);
			if (len > 0)
			{
				response[len] = '\0';
				pr_info("TCP client - received response %s\n", response);
			}
		}
	}
	
	return 0;

exit_connect:
	return -1;
}


static int __init tcp_client_init(void)
{
	pr_info("TCP client - init\n");
	
	tcp_client_connect();
	
	return 0;
}

static void __exit tcp_client_exit(void)
{
	if (conn_sock != NULL)
	{
		sock_release(conn_sock);
	}
	
	pr_info("TCP client - exit\n");
}

module_init(tcp_client_init);
module_exit(tcp_client_exit);
