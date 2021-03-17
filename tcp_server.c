#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>


#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>



#define MODULE_NAME "in-kernel TCP server"

#define DEFAULT_PORT 10100
#define MSG_LENGTH 64

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Peter Moroz");

void inet_ntoa(struct in_addr* addr, char* buff, size_t size)
{
	u_int32_t ip = addr->s_addr;
	memset(buff, 0, size);	
	sprintf(buff, "%d.%d.%d.%d", (ip) & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}



/* TCP Connection handler
*/
struct tcp_conn_handler_struct
{
	struct socket* sock;
	struct task_struct* thread;
	int stopped;
};

struct tcp_conn_handler_struct* tcp_conn_handler = NULL;

/* TCP Server
*/
struct tcp_server_struct
{
	struct task_struct* listen_thread;
	int running;	
	int stopped;
};

struct tcp_server_struct* tcp_server = NULL;


int tcp_receive(struct socket* sock, char* buffer, size_t buflen, unsigned long flags)
{
	struct msghdr msg;
	struct kvec vec;
	int len = 0;
	
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
	msg.msg_flags = 0;
	
	mmseg = get_fs();
	set_fs(KERNEL_DS);
		
repeat_send:
	vec.iov_len = left;
	vec.iov_base = (char*)buffer + written;
	
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

int tcp_connection_handler(void* arg)
{	
	struct socket* clt_sock = tcp_conn_handler->sock;
	char request[MSG_LENGTH];
	char response[MSG_LENGTH];
	int len;
	
	DECLARE_WAITQUEUE(recv_wait, current);
	
	while (1)
	{
		add_wait_queue(&clt_sock->sk->sk_wq->wait, &recv_wait);
		while (skb_queue_empty(&clt_sock->sk->sk_receive_queue))
		{
			__set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ);
			
			if (kthread_should_stop())
			{
				__set_current_state(TASK_RUNNING);
				remove_wait_queue(&clt_sock->sk->sk_wq->wait, &recv_wait);
				goto exit_handler;
			}
		}
		__set_current_state(TASK_RUNNING);
		remove_wait_queue(&clt_sock->sk->sk_wq->wait, &recv_wait);
		
		len = tcp_receive(clt_sock, request, sizeof(request), MSG_DONTWAIT);
		if (len > 0)
		{
			sprintf(response, "Response of %s", request);
			len = tcp_send(clt_sock, response, strlen(response), MSG_DONTWAIT);
			if (len < 0)
			{
				pr_err("TCP server - error (%d) when message sent\n", len);
			}
		}
		else
		{
			pr_err("TCP server - error (%d) when message received\n", len);
		}
	}
	
exit_handler:
	sock_release(tcp_conn_handler->sock);
	tcp_conn_handler->thread = NULL;
	tcp_conn_handler->stopped = 1;

	do_exit(0);
	return 0;
}


int tcp_server_listen(void* arg)
{
	int ret;
	struct socket* listen_sock = NULL;
	struct socket* clt_conn_sock = NULL;
	struct sockaddr_in addr;
	struct inet_connection_sock* isock = NULL;
	
	DECLARE_WAITQUEUE(accept_wait, current);
	
	
	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &listen_sock);
	if (ret < 0)
	{
		pr_err("TCP server - sock_create() failed, returned %d\n", ret);
		goto exit_listen1;
	}
	
	listen_sock->sk->sk_reuse = 1;
	
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(DEFAULT_PORT);
	
	ret = listen_sock->ops->bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr));
	if (ret < 0)
	{
		pr_err("TCP server - bind() failed, returned %d\n", ret);
		goto exit_listen1;
	}
	
	ret = listen_sock->ops->listen(listen_sock, 4);
	if (ret < 0)
	{
		pr_err("TCP server - listen() failed, returned %d\n", ret);
		goto exit_listen1;
	}
	
	while (1)
	{
		struct sockaddr_in clt_addr;
		char ipaddr[17];
		int addr_len = 0;
		
		if (tcp_conn_handler->sock != NULL)
		{
			pr_info("TCP server - client's connection already exist\n");
			break;
		}		
				
		clt_conn_sock = NULL;
		ret = sock_create(listen_sock->sk->sk_family, listen_sock->type,
						listen_sock->sk->sk_protocol, &clt_conn_sock);
		if (ret < 0 || clt_conn_sock == NULL)
		{
			pr_err("TCP server - listen() failed, returned %d\n", ret);
			goto exit_listen2;
		}
		
		clt_conn_sock->type = listen_sock->type;
		clt_conn_sock->ops = listen_sock->ops;
		
		isock = inet_csk(listen_sock->sk);
		
		add_wait_queue(&listen_sock->sk->sk_wq->wait, &accept_wait);
		
		while (reqsk_queue_empty(&isock->icsk_accept_queue))
		{
			__set_current_state(TASK_INTERRUPTIBLE);
			
			schedule_timeout(HZ);
			
			if (kthread_should_stop())
			{
				__set_current_state(TASK_RUNNING);
				remove_wait_queue(&listen_sock->sk->sk_wq->wait, &accept_wait);
				goto exit_listen2;
			}
		}
		
		__set_current_state(TASK_RUNNING);
		remove_wait_queue(&listen_sock->sk->sk_wq->wait, &accept_wait);
		
		pr_info("TCP server - connection accepted\n");
		ret = listen_sock->ops->accept(listen_sock, clt_conn_sock, O_NONBLOCK);
		if (ret < 0)
		{
			pr_err("TCP server - accept() failed, returned %d\n", ret);
			goto exit_listen2;
		}
		
		memset(&clt_addr, 0, sizeof(clt_addr));
		addr_len = sizeof(struct sockaddr_in);
		
		ret = clt_conn_sock->ops->getname(clt_conn_sock, (struct sockaddr*)&clt_addr, &addr_len, 2);
		if (ret < 0)
		{
			pr_err("TCP server - getname() failed, returned %d\n", ret);
			goto exit_listen2;
		}
		
		inet_ntoa(&clt_addr.sin_addr, ipaddr, sizeof(ipaddr));
		pr_info("TCP server - connection from %s:%d\n", ipaddr, ntohs(clt_addr.sin_port));
		
		tcp_conn_handler->sock = clt_conn_sock;
		tcp_conn_handler->thread = kthread_run((void *)tcp_connection_handler, NULL, MODULE_NAME/*##"tcp_connection_handler"*/);
		
		if (kthread_should_stop())
		{
			goto exit_listen1;
		}
	}
	
exit_listen2:	
	if (listen_sock != NULL)
		sock_release(clt_conn_sock);

exit_listen1:
	if (clt_conn_sock != NULL)
		sock_release(listen_sock);
		
	tcp_server->stopped = 1;
	do_exit(0);
	
	return 0;
}



int tcp_server_start(void)
{
	tcp_server->running = 1;
	tcp_server->listen_thread = kthread_run((void *)tcp_server_listen, NULL, MODULE_NAME/*##"tcp_server_listen"*/);
	return 0;
}

static int __init tcp_server_init(void)
{
	pr_info("TCP server - init\n");
	
	tcp_server = kmalloc(sizeof(struct tcp_server_struct), GFP_KERNEL);
	memset(tcp_server, 0, sizeof(struct tcp_server_struct));
		
	tcp_conn_handler = kmalloc(sizeof(struct tcp_conn_handler_struct), GFP_KERNEL);
	memset(tcp_conn_handler, 0, sizeof(struct tcp_conn_handler_struct));
	
	tcp_server_start();
	
	return 0;
}

static void __exit tcp_server_exit(void)
{
	int ret;
	
	if (tcp_server != NULL)
	{
		if (tcp_server->listen_thread != NULL && !tcp_server->stopped)
		{
			pr_info("TCP server - stopping listen thread...\n");
			ret = kthread_stop(tcp_server->listen_thread);
			if (ret)
				pr_err("TCP server - kthread_stop() failed, returned %d\n", ret);
			else
				pr_info("TCP server - stopping thread successfull\n");
				
			tcp_server->listen_thread = NULL;
			tcp_server->stopped = 1;
		}
		
		kfree(tcp_server);
	}
	
	if (tcp_conn_handler != NULL)
	{
		if (tcp_conn_handler->thread != NULL && !tcp_conn_handler->stopped)
		{
			pr_info("TCP server - stopping connection handler thread...\n");
			ret = kthread_stop(tcp_conn_handler->thread);
			if (ret)
				pr_err("TCP server - kthread_stop() failed, returned %d\n", ret);
			else
				pr_info("TCP server - stopping thread successfull\n");
				
			tcp_conn_handler->thread = NULL;
			tcp_conn_handler->stopped = 1;
		}
		
		kfree(tcp_conn_handler);
	}
	
	pr_info("TCP server - exit\n");
}

module_init(tcp_server_init);
module_exit(tcp_server_exit);
