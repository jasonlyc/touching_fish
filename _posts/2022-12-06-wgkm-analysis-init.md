---
title: WireGuard Kernel Module Analysis - Interface Initialization
author: Yuchen Liu
date: 2022-12-06
layout: post
---
#### Overview
Here is a call graph for functions that are related to interface initialization.
* mod_init [main.c]
  * wg_device_init [device.c]
    * register_pernet_device(struct pernet_operations*)
      * wg_netns_pre_exit [device.c] : hook function that will be invoked before the interface leaves the netns
    * rtnl_link_register(struct rtnl_link_ops*)
      * wg_setup [device.c]: hook function that will be invoked in netlink set operation
        * struct net_devives_ops
          * wg_open [device.c]: hook function that will be invoked when net device is brought up
          * wg_stop [device.c]: hook function that will be invoked when net device is brought down
          * wg_xmit [device.c]: hook function that will be invoked when packet needs to be transmitted via the net device
      * wg_newlink [device.c]: hook function that will be invoked in netlink creation operation
  * wg_genetlink_init [netlink.c]
    * genl_register_family
      * struct genl_ops
        * WG_CMD_GET_DEVICE
        * WG_CMD_SET_DEVICE

#### Entrypoint
The kernel module entry point function is `mod_init` in main.c:
<figure>
	<figcaption>main.c</figcaption>
{% highlight c linenos %}
static int __init mod_init(void)
{
	int ret;

	if ((ret = chacha20_mod_init()) || (ret = poly1305_mod_init()) ||
	    (ret = chacha20poly1305_mod_init()) || (ret = blake2s_mod_init()) ||
	    (ret = curve25519_mod_init()))
		return ret;

#ifdef DEBUG
	if (!wg_allowedips_selftest() || !wg_packet_counter_selftest() ||
	    !wg_ratelimiter_selftest())
		return -ENOTRECOVERABLE;
#endif
	wg_noise_init();

	ret = wg_device_init();
	if (ret < 0)
		goto err_device;

	ret = wg_genetlink_init();
	if (ret < 0)
		goto err_netlink;

	pr_info("WireGuard " WIREGUARD_VERSION " loaded. See www.wireguard.com for information.\n");
	pr_info("Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.\n");

	return 0;

err_netlink:
	wg_device_uninit();
err_device:
	return ret;
}

module_init(mod_init);
{% endhighlight %}
</figure>

Multiple cryptography modules and noise module are initialized at the beginning. I will not dig into details of cryptography in this article. Instead, more details in the following two functions: `wg_device_init` and `wg_genetlink_init` will be inspected.


#### wg_device_init
<figure>
	<figcaption>device.c</figcaption>
{% highlight c linenos %}
int __init wg_device_init(void)
{
	int ret;

#ifdef CONFIG_PM_SLEEP
	ret = register_pm_notifier(&pm_notifier);
	if (ret)
		return ret;
#endif

	ret = register_pernet_device(&pernet_ops);
	if (ret)
		goto error_pm;

	ret = rtnl_link_register(&link_ops);
	if (ret)
		goto error_pernet;

	return 0;

error_pernet:
	unregister_pernet_device(&pernet_ops);
error_pm:
#ifdef CONFIG_PM_SLEEP
	unregister_pm_notifier(&pm_notifier);
#endif
	return ret;
}
{% endhighlight %}
</figure>

In order to integrate with the existing ip(8) utilities and the netlink-based Linux user space, the kernel’s RTNL layer is used for registering a virtual interface, known inside the kernel as a “link”. This easily gives access to
the kernel APIs accessed by ip-link(8) and ip-set(8). [<sup>1</sup>](#refer-anchor-1)

`register_pernet_device` is called in line 11 above. The passed in argument is a `struct pernet_operations` containing function pointers for network namespace related operations:

<figure>
	<figcaption>device.c</figcaption>
{% highlight c linenos %}
static struct pernet_operations pernet_ops = {
	.pre_exit = wg_netns_pre_exit
};
{% endhighlight %}
</figure>
`.pre_exit` hook will be invoked before a network namespace is removed. We can imagine some cleanup works will be done in `wg_netns_pre_exit`.
<figure>
	<figcaption>device.c</figcaption>
{% highlight c linenos %}
static void wg_netns_pre_exit(struct net *net)
{
	struct wg_device *wg;

	rtnl_lock();
	list_for_each_entry(wg, &device_list, device_list) {
		if (rcu_access_pointer(wg->creating_net) == net) {
			pr_debug("%s: Creating namespace exiting\n", wg->dev->name);
			netif_carrier_off(wg->dev);
			mutex_lock(&wg->device_update_lock);
			rcu_assign_pointer(wg->creating_net, NULL);
			wg_socket_reinit(wg, NULL, NULL);
			mutex_unlock(&wg->device_update_lock);
		}
	}
	rtnl_unlock();
}
{% endhighlight %}
</figure>
`device_list` stores all `wg_device` struct that are created. The function traverses the list to check if a `wg_device` struct is in the specific network namespace. If yes, the underlying socket will be released in `wg_socket_reinit`.

`rtnl_link_register` is called afterwards. The passed in argument is a `struct rtnl_link_ops` containing function pointers for network device creation and configuration:
{% highlight c linenos %}
static struct rtnl_link_ops link_ops __read_mostly = {
	.kind			= KBUILD_MODNAME,
	.priv_size		= sizeof(struct wg_device),
	.setup			= wg_setup,
	.newlink		= wg_newlink,
};
{% endhighlight %}
To create a wireguard interface in user space using iproute2 utilities, we usually use the following command:
```bash
ip link add dev wg0 type wireguard
```
The `ip` command will use RTNL command to talk to the kernel. Here the `.kind` is set to literal string `wireguard`, which matches the type parameter in ip-link command. `.priv_size` indicates the number of bytes that will be reserved for the private data of the corresponding `struct net_device` object. We will see how the private data will be used later. When a wireguard device is created, `wg_newlink` and `wg_setup` will be invoked. We will look into each of them in the following sections.

#### wg_newlink
<figure>
	<figcaption>device.c</figcaption>
{% highlight c linenos %}
static int wg_newlink(struct net *src_net, struct net_device *dev,
		      struct nlattr *tb[], struct nlattr *data[],
		      struct netlink_ext_ack *extack)
{
	struct wg_device *wg = netdev_priv(dev);
}
{% endhighlight %}
</figure>
The private data is converted to a `struct wg_device`. Remember that the `.priv_size` is initialized to `sizeof(struct wg_device)`. If you are interested in how the RTNL allocates the space for `struct net_device` and its private data, you can take a look at function `rtnl_create_link` in /net/core/rtnetlink.c.

More work will be done to initialize fields in this `struct wg_device` in `wg_newlink`. I will just briefly walk through the workqueue initialization in this function.
<figure>
	<figcaption>wg_newlink in device.c</figcaption>
{% highlight c linenos %}
	wg->handshake_receive_wq = alloc_workqueue("wg-kex-%s",
			WQ_CPU_INTENSIVE | WQ_FREEZABLE, 0, dev->name);
	if (!wg->handshake_receive_wq)
		goto err_free_incoming_handshakes;

	wg->handshake_send_wq = alloc_workqueue("wg-kex-%s",
			WQ_UNBOUND | WQ_FREEZABLE, 0, dev->name);
	if (!wg->handshake_send_wq)
		goto err_destroy_handshake_receive;

	wg->packet_crypt_wq = alloc_workqueue("wg-crypt-%s",
			WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 0, dev->name);
	if (!wg->packet_crypt_wq)
		goto err_destroy_handshake_send;

	ret = wg_packet_queue_init(&wg->encrypt_queue, wg_packet_encrypt_worker,
				   true, MAX_QUEUED_PACKETS);
	if (ret < 0)
		goto err_destroy_packet_crypt;

	ret = wg_packet_queue_init(&wg->decrypt_queue, wg_packet_decrypt_worker,
				   true, MAX_QUEUED_PACKETS);
	if (ret < 0)
		goto err_free_encrypt_queue;
{% endhighlight %}
</figure>
The WireGuard kernel module uses concurrency managed workdqueue (cmwq)[<sup>2</sup>](#refer-anchor-2) to run packet encryption/decryption, and key exchange logic in asynchronous process execution context. In this series, I will focus on encryption/decryption workqueue, which is allocated by calling `alloc_workqueue` in line 10. The first parameter will be used as the kernel worker thread name, which can be seen in `top` command output:
```
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
3093610 root      20   0       0      0      0 I   0.8   0.0   0:03.25 kworker/2:0-wg-crypt-wg0
2519903 root      20   0       0      0      0 I   0.4   0.0   0:48.15 kworker/1:1-wg-crypt-wg0
2904067 root      20   0       0      0      0 I   0.4   0.0   0:57.10 kworker/2:2-wg-crypt-wg0
3008785 root      20   0       0      0      0 I   0.4   0.0   0:09.58 kworker/3:0-wg-crypt-wg0
3060153 root      20   0       0      0      0 I   0.4   0.0   0:07.51 kworker/0:2-wg-crypt-wg0
3078102 root      20   0       0      0      0 I   0.4   0.0   0:03.43 kworker/3:3-wg-crypt-wg0
3099580 root      20   0       0      0      0 I   0.4   0.0   0:02.20 kworker/1:4-wg-crypt-wg0
2789807 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 wg-crypt-wg0
3055117 root      20   0       0      0      0 I   0.0   0.0   0:05.47 kworker/1:0-wg-crypt-wg0
3075421 root      20   0       0      0      0 I   0.0   0.0   0:03.31 kworker/2:1-wg-crypt-wg0
```
The second parameter specifies the flag. `WG_CPU_INTENSIVE` and `WG_MEM_RECLAIM` are used. `WG_CPU_INTENSIVE` makes work items in this wq will not prevent other work items in the same worker-pool from starting execution. `WG_MEM_RECLAIM` is set because network device can be used during memory reclaim, wq needs **forward progress guarantee under memory pressure**.
<figure>
	<figcaption>wg_newlink in device.c</figcaption>
{% highlight c linenos %}
	ret = wg_packet_queue_init(&wg->encrypt_queue, wg_packet_encrypt_worker,
				   true, MAX_QUEUED_PACKETS);
	if (ret < 0)
		goto err_destroy_packet_crypt;

	ret = wg_packet_queue_init(&wg->decrypt_queue, wg_packet_decrypt_worker,
				   true, MAX_QUEUED_PACKETS);
{% endhighlight %}
</figure>
Then `encrypt_queue` and `decrypt_queue` are initialized. Let's step into `wg_packet_queue_init`.
<figure>
	<figcaption>queueing.c</figcaption>
{% highlight c linenos %}
int wg_packet_queue_init(struct crypt_queue *queue, work_func_t function,
			 bool multicore, unsigned int len)
{
	int ret;

	memset(queue, 0, sizeof(*queue));
	ret = ptr_ring_init(&queue->ring, len, GFP_KERNEL);
	if (ret)
		return ret;
	if (function) {
		if (multicore) {
			queue->worker = wg_packet_percpu_multicore_worker_alloc(
				function, queue);
			if (!queue->worker) {
				ptr_ring_cleanup(&queue->ring, NULL);
				return -ENOMEM;
			}
		} else {
			INIT_WORK(&queue->work, function);
		}
	}
	return 0;
}

struct multicore_worker __percpu *
wg_packet_percpu_multicore_worker_alloc(work_func_t function, void *ptr)
{
	int cpu;
	struct multicore_worker __percpu *worker =
		alloc_percpu(struct multicore_worker);

	if (!worker)
		return NULL;

	for_each_possible_cpu(cpu) {
		per_cpu_ptr(worker, cpu)->ptr = ptr;
		INIT_WORK(&per_cpu_ptr(worker, cpu)->work, function);
	}
	return worker;
}

struct multicore_worker {
	void *ptr;
	struct work_struct work;
};

struct crypt_queue {
	struct ptr_ring ring;
	union {
		struct {
			struct multicore_worker __percpu *worker;
			int last_cpu;
		};
		struct work_struct work;
	};
};
{% endhighlight%}
</figure>
A `struct crypt_queue` object will be initialized in `wg_packet_queue_init`. An internal ring buffer is initialized with size set to `MAX_QUEUED_PACKETS`. If `multicore` is set, it will initialize a `__percpu` `struct multicore_worker` and saves the pointer to the work item function. In conclusion, `struct crypt_queue` maintains a mapping between packet encryption/decryption function and the corresponding packet ring buffer.

<figure>
	<figcaption>wg_newlink in device.c</figcaption>
{% highlight c linenos %}
	ret = register_netdevice(dev);
	if (ret < 0)
		goto err_uninit_ratelimiter;

	list_add(&wg->device_list, &device_list);
{% endhighlight %}
</figure>
`register_netdevice` is invoked at the end of `wg_newlink`, and the initialized `struct wg_device` is added to the `device_list` variable that is maintained in the kernel module.


#### wg_setup
<figure>
	<figcaption>device.c</figcaption>
{% highlight c linenos %}
static void wg_setup(struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);
	enum { WG_NETDEV_FEATURES = NETIF_F_HW_CSUM | NETIF_F_RXCSUM |
				    NETIF_F_SG | NETIF_F_GSO |
				    NETIF_F_GSO_SOFTWARE | NETIF_F_HIGHDMA };
	const int overhead = MESSAGE_MINIMUM_LENGTH + sizeof(struct udphdr) +
			     max(sizeof(struct ipv6hdr), sizeof(struct iphdr));

	dev->netdev_ops = &netdev_ops;
	dev->header_ops = &ip_tunnel_header_ops;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->needed_headroom = DATA_PACKET_HEAD_ROOM;
	dev->needed_tailroom = noise_encrypted_len(MESSAGE_PADDING_MULTIPLE);
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;
#ifndef COMPAT_CANNOT_USE_IFF_NO_QUEUE
	dev->priv_flags |= IFF_NO_QUEUE;
#else
	dev->tx_queue_len = 0;
#endif
	dev->features |= NETIF_F_LLTX;
	dev->features |= WG_NETDEV_FEATURES;
	dev->hw_features |= WG_NETDEV_FEATURES;
	dev->hw_enc_features |= WG_NETDEV_FEATURES;
	dev->mtu = ETH_DATA_LEN - overhead;
#ifndef COMPAT_CANNOT_USE_MAX_MTU
	dev->max_mtu = round_down(INT_MAX, MESSAGE_PADDING_MULTIPLE) - overhead;
#endif

	SET_NETDEV_DEVTYPE(dev, &device_type);

	/* We need to keep the dst around in case of icmp replies. */
	netif_keep_dst(dev);

	memset(wg, 0, sizeof(*wg));
	wg->dev = dev;
}
{% endhighlight %}
</figure>
`wg_setup` function mainly initializes fields of the passed in `struct net_device` object, e.g., type, flags, mtu, features, netdev_ops. Before going into details of `netdev_ops`, let's take a quick look at the features. These features can be inspected by running `ethtool -k wg0`, e.g., generic-segmentation-offload, scatter-gather, tx-lockless, etc.
<figure>
	<figcaption>device.c</figcaption>
{% highlight c linenos %}
static const struct net_device_ops netdev_ops = {
	.ndo_open		= wg_open,
	.ndo_stop		= wg_stop,
	.ndo_start_xmit		= wg_xmit,
	.ndo_get_stats64	= ip_tunnel_get_stats64
};
{% endhighlight %}
</figure>
Lile `struct rtnl_link_ops` that we introduced before, `struct net_device_ops` also defines the management hooks for network devices. We will step into `.ndo_open` function, which will be called when a network device transitions to the up state.
<figure>
	<figcaption>device.c</figcaption>
{% highlight c linenos %}
static int wg_open(struct net_device *dev)
{
	struct in_device *dev_v4 = __in_dev_get_rtnl(dev);
#ifndef COMPAT_CANNOT_USE_IN6_DEV_GET
	struct inet6_dev *dev_v6 = __in6_dev_get(dev);
#endif
	struct wg_device *wg = netdev_priv(dev);
	struct wg_peer *peer;
	int ret;

	if (dev_v4) {
		/* At some point we might put this check near the ip_rt_send_
		 * redirect call of ip_forward in net/ipv4/ip_forward.c, similar
		 * to the current secpath check.
		 */
		IN_DEV_CONF_SET(dev_v4, SEND_REDIRECTS, false);
		IPV4_DEVCONF_ALL(dev_net(dev), SEND_REDIRECTS) = false;
	}
#ifndef COMPAT_CANNOT_USE_IN6_DEV_GET
	if (dev_v6)
#ifndef COMPAT_CANNOT_USE_DEV_CNF
		dev_v6->cnf.addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;
#else
		dev_v6->addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;
#endif
#endif

	mutex_lock(&wg->device_update_lock);
	ret = wg_socket_init(wg, wg->incoming_port);
	if (ret < 0)
		goto out;
	list_for_each_entry(peer, &wg->peer_list, peer_list) {
		wg_packet_send_staged_packets(peer);
		if (peer->persistent_keepalive_interval)
			wg_packet_send_keepalive(peer);
	}
out:
	mutex_unlock(&wg->device_update_lock);
	return ret;
}
{% endhighlight %}
</figure>
The core function here is `wg_socket_init`. We can imagine the UDP socket is created in this function, but let's step into this function for more detail:
<figure>
	<figcaption>socket.c</figcaption>
{% highlight c linenos %}
int wg_socket_init(struct wg_device *wg, u16 port)
{
	struct net *net;
	int ret;
	struct udp_tunnel_sock_cfg cfg = {
		.sk_user_data = wg,
		.encap_type = 1,
		.encap_rcv = wg_receive
	};
	struct socket *new4 = NULL, *new6 = NULL;
	struct udp_port_cfg port4 = {
		.family = AF_INET,
		.local_ip.s_addr = htonl(INADDR_ANY),
		.local_udp_port = htons(port),
		.use_udp_checksums = true
	};
{% endhighlight %}
</figure>
A `struct udp_tunnel_sock_cfg` is initialized at the beginning. As `encap_rev` points to a function, we can imagine this is another hook function that will be called later.
<figure>
	<figcaption>socket.c</figcaption>
{% highlight c linenos %}
	rcu_read_lock();
	net = rcu_dereference(wg->creating_net);
	net = net ? maybe_get_net(net) : NULL;
	rcu_read_unlock();
	if (unlikely(!net))
		return -ENONET;

#if IS_ENABLED(CONFIG_IPV6)
retry:
#endif

	ret = udp_sock_create(net, &port4, &new4);
	if (ret < 0) {
		pr_err("%s: Could not create IPv4 socket\n", wg->dev->name);
		goto out;
	}
	set_sock_opts(new4);
	setup_udp_tunnel_sock(net, new4, &cfg);
{% endhighlight %}
</figure>
Then a UDP socket `struct socket` is initialized, which listens on `INADDR_ANY` and the specified port. `struct udp_tunnel_sock_cfg` that contains the hook function pointer is passed to `setup_udp_tunnel_sock`.
<figure>
	<figcaption>compat/udp_tunnel/udp_tunnel.c</figcaption>
{% highlight c linenos %}
static udp_tunnel_encap_rcv_t encap_rcv = NULL;
static void __compat_sk_data_ready(struct sock *sk
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
			      ,int unused_vulnerable_length_param
#endif
			      )
{
	struct sk_buff *skb;
	while ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		skb_orphan(skb);
		sk_mem_reclaim(sk);
		encap_rcv(sk, skb);
	}
}

void setup_udp_tunnel_sock(struct net *net, struct socket *sock,
			   struct udp_tunnel_sock_cfg *cfg)
{
	inet_sk(sock->sk)->mc_loop = 0;
	encap_rcv = cfg->encap_rcv;
	rcu_assign_sk_user_data(sock->sk, cfg->sk_user_data);
	/* We force the cast in this awful way, due to various Android kernels
	 * backporting things stupidly. */
	*(void **)&sock->sk->sk_data_ready = (void *)__compat_sk_data_ready;
}
{% endhighlight%}
</figure>
The `encap_rev` function will be called in `__compat_sk_data_ready`, which is also a hook function that will be called when there is data available on the receive queue of `struct sock`.
<figure>
	<figcaption>wg_socket_init in socket.c</figcaption>
{% highlight c linenos %}
	wg_socket_reinit(wg, new4->sk, new6 ? new6->sk : NULL);
	ret = 0;
out:
	put_net(net);
	return ret;
}
{% endhighlight %}
</figure>
`wg_socket_reinit` is called to save the created `struct sock` into `struct wg_device` object at the end of the `wg_socket_init` function.

#### wg_genetlink_init
Back into the mod_init in main.c. The last function that we will step into is `wg_genetlink_init`.
<figure>
	<figcaption>netlink.c</figcaption>
{% highlight c linenos %}
static struct genl_family genl_family
#ifndef COMPAT_CANNOT_USE_GENL_NOPS
__ro_after_init = {
	.ops = genl_ops,
	.n_ops = ARRAY_SIZE(genl_ops),
#else
= {
#endif
	.name = WG_GENL_NAME,
	.version = WG_GENL_VERSION,
	.maxattr = WGDEVICE_A_MAX,
	.module = THIS_MODULE,
#ifndef COMPAT_CANNOT_INDIVIDUAL_NETLINK_OPS_POLICY
	.policy = device_policy,
#endif
	.netnsok = true
};

int __init wg_genetlink_init(void)
{
	return genl_register_family(&genl_family);
}
{% endhighlight %}
</figure>
All in all, a `struct genl_ops` is registered into Generic Netlink protocol family. Let's take a look at the `struct genl_ops`.
<figure>
	<figcaption>netlink.c</figcaption>
{% highlight c linenos %}
struct genl_ops genl_ops[] = {
	{
		.cmd = WG_CMD_GET_DEVICE,
#ifndef COMPAT_CANNOT_USE_NETLINK_START
		.start = wg_get_device_start,
#endif
		.dumpit = wg_get_device_dump,
		.done = wg_get_device_done,
#ifdef COMPAT_CANNOT_INDIVIDUAL_NETLINK_OPS_POLICY
		.policy = device_policy,
#endif
		.flags = GENL_UNS_ADMIN_PERM
	}, {
		.cmd = WG_CMD_SET_DEVICE,
		.doit = wg_set_device,
#ifdef COMPAT_CANNOT_INDIVIDUAL_NETLINK_OPS_POLICY
		.policy = device_policy,
#endif
		.flags = GENL_UNS_ADMIN_PERM
	}
};
{% endhighlight %}
</figure>
Two Generic Netlink operations are registered. `WG_CMD_GET_DEVICE` is to get information of the wireguard device. `WG_CMD_SET_DEVICE` is to set configuration of the device. If we usethe userspace `wg` command to dump the configuration of a wireguard interface and use `strace` to dump the system call traces, we will find the following calls:
```bash
$ sudo strace wg showconf wg0
......
socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC) = 3
bind(3, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 0
getsockname(3, {sa_family=AF_NETLINK, nl_pid=2498680, nl_groups=00000000}, [12]) = 0
sendto(3, [{nlmsg_len=36, nlmsg_type=nlctrl, nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK, nlmsg_seq=1670397475, nlmsg_pid=0}, "\x03\x01\x00\x00\x0e\x00\x02\x00\x77\x69\x72\x65\x67\x75\x61\x72\x64\x00\x00\x00"], 36, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 36
recvmsg(3, {msg_name={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, msg_namelen=12, msg_iov=[{iov_base=[{nlmsg_len=112, nlmsg_type=nlctrl, nlmsg_flags=0, nlmsg_seq=1670397475, nlmsg_pid=2498680}, "\x01\x02\x00\x00\x0e\x00\x02\x00\x77\x69\x72\x65\x67\x75\x61\x72\x64\x00\x00\x00\x06\x00\x01\x00\x22\x00\x00\x00\x08\x00\x03\x00"...], iov_len=4096}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 112
recvmsg(3, {msg_name={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, msg_namelen=12, msg_iov=[{iov_base=[{nlmsg_len=36, nlmsg_type=NLMSG_ERROR, nlmsg_flags=NLM_F_CAPPED, nlmsg_seq=1670397475, nlmsg_pid=2498680}, {error=0, msg={nlmsg_len=36, nlmsg_type=nlctrl, nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK, nlmsg_seq=1670397475, nlmsg_pid=0}}], iov_len=4096}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 36
sendto(3, [{nlmsg_len=28, nlmsg_type=wireguard, nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK|0x300, nlmsg_seq=1670397475, nlmsg_pid=0}, "\x00\x01\x00\x00\x08\x00\x02\x00\x77\x67\x30\x00"], 28, 0, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 28
recvmsg(3, {msg_name={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, msg_namelen=12, msg_iov=[{iov_base=[[{nlmsg_len=296, nlmsg_type=wireguard, nlmsg_flags=NLM_F_MULTI, nlmsg_seq=1670397475, nlmsg_pid=2498680}, "\x00\x01\x00\x00\x06\x00\x06\x00\x6c\xca\x00\x00\x08\x00\x07\x00\x06\x00\x00\x00\x08\x00\x01\x00\xf3\x0a\x00\x00\x08\x00\x02\x00"...], [{nlmsg_len=20, nlmsg_type=NLMSG_DONE, nlmsg_flags=NLM_F_MULTI, nlmsg_seq=1670397475, nlmsg_pid=2498680}, 0]], iov_len=4096}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 316
close(3)                                = 0
......
```
The last `sendto` call corresponds to the `WG_CMD_GET_DEVICE` command, and you can find `\x6x\xca` in the subsequent received message, which indicates the listen port is 51820.

#### Summary
In this article, I briefly walk through the WireGuard device initialization workflow.

WireGuard utilizes kernel's RTNL layer to register different hook functions for virtual interface initialization and configuration. Workqueues for datagram reception/transmission are initialized in the `wg_newlink` as `.newlink` hook function of `struct rtnl_link_ops`. UDP socket is created in `wg_open` as `.ndo_open` hook function of `struct net_device_ops`, which is registered into `struct net_device` in the `wg_setup` as `.setup` hook function of `struct rtnl_link_ops`. Generic Netlink protocol is used to support userspace tool `wg`.

#### References
<div id="refer-anchor-1"></div>
- [1] [WireGuard Whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
<div id="refer-anchor-2"></div>
- [2] [Concurrency Managed Workqueue](https://docs.kernel.org/core-api/workqueue.html)
