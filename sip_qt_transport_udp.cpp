#include "sip_qt_transport_udp.h"
#include <QUdpSocket>
#include <QNetworkDatagram>

#include "pj/assert.h"
#include "pj/errno.h"
#include "pj/string.h"
#include "pj/os.h"
#include "pj/sock.h"
#include "pj/pool.h"
#include "pj/log.h"
#include "pj/addr_resolv.h"
#include "pjsip/sip_transport.h"
#include "pjsip/sip_endpoint.h"

// 这个函数里面最好不要加入虚函数等内容，否则会导致内存布局与C语言不符合
struct qt_sip_udp_transport
{
public:
	pjsip_transport base;		// sip的pjsip内容，记得要把这个放在头部，否则进行强转的时候会出问题
	QUdpSocket *socket; // qt的socket
};

// 当接QUdpSocket接收到UDP消息的时候,会触发次函数
static void on_recv_udp_msg(qt_sip_udp_transport* transport);

// 主动检查qt_sip_udp_transport这个结构体，由于需要与C语言进行交互，所以最好不要加入C++的特性，比如virtual function，
// 这样会导致内存布局被加入virtual table等，破坏内存布局
static void AutoCheck();

static pj_status_t get_published_name(pj_sock_t sock,char hostbuf[],int hostbufsz,pjsip_host_port *bound_name);

static pj_status_t udp_send_msg(pjsip_transport *transport,
								pjsip_tx_data *tdata,
								const pj_sockaddr_t *rem_addr,
								int addr_len,
								void *token,
								pjsip_transport_callback callback);

static pj_status_t udp_destroy(pjsip_transport* transport);

static pj_status_t udp_shutdown(pjsip_transport* transport);

static void init_rx_data(qt_sip_udp_transport* transport, pjsip_rx_data* rdata );


static void AutoCheck()
{
	static_assert( std::is_pod<qt_sip_udp_transport>::value, "not pod of qt_sip_transport");
}

static void on_recv_udp_msg(qt_sip_udp_transport* transport)
{
	while (transport->socket->hasPendingDatagrams())
	{
		QNetworkDatagram datagram = transport->socket->receiveDatagram();
		
		pjsip_rx_data rx_data;
		memset(&rx_data, 0, sizeof(rx_data));
		init_rx_data(transport, &rx_data);

		const pj_sockaddr* src_addr = &(rx_data.pkt_info.src_addr);

		rx_data.pkt_info.src_addr.ipv4.sin_family = pj_AF_INET();
		rx_data.pkt_info.src_addr.ipv4.sin_port = datagram.senderPort();
		rx_data.pkt_info.src_addr.ipv4.sin_addr.s_addr = datagram.senderAddress().toIPv4Address();

		QByteArray packet = datagram.data();
		strncpy_s(rx_data.pkt_info.packet, packet.data(), packet.size());
		
		QByteArray data = datagram.data();
		rx_data.pkt_info.len = data.length();
		rx_data.pkt_info.zero = 0;
		pj_gettimeofday(&rx_data.pkt_info.timestamp);

		QByteArray addr = datagram.senderAddress().toString().toLatin1();
		strncpy_s(rx_data.pkt_info.src_name, addr.data(), addr.length());

	    rx_data.pkt_info.src_port = pj_sockaddr_get_port(src_addr);

		pj_size_t size_eaten = 
		pjsip_tpmgr_receive_packet(rx_data.tp_info.transport->tpmgr, 
					   &rx_data);

		if (size_eaten < 0)
		{
			qWarning() << "on_recv_udp_msg should not happend!";
		}
		rx_data.pkt_info.len = 0;
	}
}


// 直接从sip_transport_udp里面 拷贝过来
/* Generate transport's published address */
static pj_status_t get_published_name(pj_sock_t sock,
				      char hostbuf[],
				      int hostbufsz,
				      pjsip_host_port *bound_name)
{
    pj_sockaddr tmp_addr;
    int addr_len;
    pj_status_t status;

    addr_len = sizeof(tmp_addr);
    status = pj_sock_getsockname(sock, &tmp_addr, &addr_len);
    if (status != PJ_SUCCESS)
	return status;

    bound_name->host.ptr = hostbuf;
    if (tmp_addr.addr.sa_family == pj_AF_INET()) {
	bound_name->port = pj_ntohs(tmp_addr.ipv4.sin_port);

	/* If bound address specifies "0.0.0.0", get the IP address
	 * of local hostname.
	 */
	if (tmp_addr.ipv4.sin_addr.s_addr == PJ_INADDR_ANY) {
	    pj_sockaddr hostip;

	    status = pj_gethostip(pj_AF_INET(), &hostip);
	    if (status != PJ_SUCCESS)
		return status;

	    status = pj_inet_ntop(pj_AF_INET(), &hostip.ipv4.sin_addr,
	    		 	  hostbuf, hostbufsz);
	} else {
	    /* Otherwise use bound address. */
	    status = pj_inet_ntop(pj_AF_INET(), &tmp_addr.ipv4.sin_addr,
	    		 	  hostbuf, hostbufsz);
	}

    } else {
	/* If bound address specifies "INADDR_ANY" (IPv6), get the
         * IP address of local hostname
         */
	pj_uint32_t loop6[4] = { 0, 0, 0, 0};

	bound_name->port = pj_ntohs(tmp_addr.ipv6.sin6_port);

	if (pj_memcmp(&tmp_addr.ipv6.sin6_addr, loop6, sizeof(loop6))==0) {
	    status = pj_gethostip(tmp_addr.addr.sa_family, &tmp_addr);
	    if (status != PJ_SUCCESS)
		return status;
	}

	status = pj_inet_ntop(tmp_addr.addr.sa_family, 
			      pj_sockaddr_get_addr(&tmp_addr),
			      hostbuf, hostbufsz);
    }
    if (status == PJ_SUCCESS) {
	bound_name->host.slen = pj_ansi_strlen(hostbuf);
    }


    return status;
}

pj_status_t qt_sip_transport_create(const int port, pjsip_endpoint* endpt, qt_sip_udp_transport** ptp)
{
	*ptp = (qt_sip_udp_transport*)malloc(sizeof(qt_sip_udp_transport));
	qt_sip_udp_transport* tp = *ptp;
	// 初始化udp
	pj_pool_t *pool;
    const char *format, *ipv6_quoteb = "", *ipv6_quotee = "";
    unsigned i;
    pj_status_t status;

	// 创建qt的内容
	tp->socket = new QUdpSocket();
	tp->socket->bind(port);
	std::function< void(void)> fn =
		std::bind(on_recv_udp_msg, tp);
	QObject::connect(tp->socket, &QUdpSocket::readyRead, fn);

    /* Create pool. */

    pool = pjsip_endpt_create_pool(endpt, "qt udp", PJSIP_POOL_LEN_TRANSPORT, 
				   PJSIP_POOL_INC_TRANSPORT);
    if (!pool)
	return PJ_ENOMEM;

    /* Save pool. */
    tp->base.pool = pool;

    pj_memcpy(tp->base.obj_name, pool->obj_name, PJ_MAX_OBJ_NAME);

    /* Init reference counter. */
    status = pj_atomic_create(pool, 0, &tp->base.ref_cnt);
    if (status != PJ_SUCCESS)
	goto on_error;

    /* Init lock. */
    status = pj_lock_create_recursive_mutex(pool, pool->obj_name, 
					    &tp->base.lock);
    if (status != PJ_SUCCESS)
	goto on_error;

    /* Set type. */
    tp->base.key.type = PJSIP_TRANSPORT_UDP;		// 这里改成固定是udp

    /* Remote address is left zero (except the family) */
    tp->base.key.rem_addr.addr.sa_family = (pj_uint16_t)(pj_AF_INET());

    /* Type name. */
    tp->base.type_name = "UDP";

    /* Transport flag */
    tp->base.flag = pjsip_transport_get_flag_from_type(PJSIP_TRANSPORT_UDP);


    /* Length of addressess. */
    tp->base.addr_len = sizeof(tp->base.local_addr);

    /* Init local address. */
    status = pj_sock_getsockname(tp->socket->socketDescriptor(), &tp->base.local_addr, 
				 &tp->base.addr_len);
    if (status != PJ_SUCCESS)
	goto on_error;

    /* Init remote name. */
    //if (type == PJSIP_TRANSPORT_UDP)
	tp->base.remote_name.host = pj_str("0.0.0.0");

#if 0
    else
	tp->base.remote_name.host = pj_str("::0");
    tp->base.remote_name.port = 0;
#endif


    /* Init direction */
    tp->base.dir = PJSIP_TP_DIR_NONE;

    /* Set endpoint. */
    tp->base.endpt = endpt;

    /* Transport manager and timer will be initialized by tpmgr */

    /* Attach socket and assign name. */
	char addr_buf[PJ_INET6_ADDRSTRLEN];
	pjsip_host_port addr_name;
	status = get_published_name(tp->socket->socketDescriptor(), addr_buf, sizeof(addr_buf), &tp->base.local_name);

#if 0
    /* Register to ioqueue */
    status = register_to_ioqueue(tp);
    if (status != PJ_SUCCESS)
	goto on_error;
#endif

    /* Set functions. */
    tp->base.send_msg = &udp_send_msg;
    tp->base.do_shutdown = &udp_shutdown;
    tp->base.destroy = &udp_destroy;

    /* This is a permanent transport, so we initialize the ref count
     * to one so that transport manager don't destroy this transport
     * when there's no user!
     */
    pj_atomic_inc(tp->base.ref_cnt);

    /* Register to transport manager. */
    tp->base.tpmgr = pjsip_endpt_get_tpmgr(endpt);
    status = pjsip_transport_register( tp->base.tpmgr, (pjsip_transport*)tp);
    if (status != PJ_SUCCESS)
	goto on_error;

#if 0

    /* Create rdata and put it in the array. */
    tp->rdata_cnt = 0;
    tp->rdata = (pjsip_rx_data**)
    		pj_pool_calloc(tp->base.pool, async_cnt, 
			       sizeof(pjsip_rx_data*));
    for (i=0; i<async_cnt; ++i) {
	pj_pool_t *rdata_pool = pjsip_endpt_create_pool(endpt, "rtd%p", 
							PJSIP_POOL_RDATA_LEN,
							PJSIP_POOL_RDATA_INC);
	if (!rdata_pool) {
	    pj_atomic_set(tp->base.ref_cnt, 0);
	    pjsip_transport_destroy(&tp->base);
	    return PJ_ENOMEM;
	}

	init_rdata(tp, i, rdata_pool, NULL);
	tp->rdata_cnt++;
    }

    /* Start reading the ioqueue. */
    status = start_async_read(tp);
    if (status != PJ_SUCCESS) {
	pjsip_transport_destroy(&tp->base);
	return status;
    }

#endif
    PJ_LOG(4,(tp->base.obj_name, 
	      "SIP %s started, published address is %s%.*s%s:%d",
	      pjsip_transport_get_type_desc((pjsip_transport_type_e)tp->base.key.type),
	      ipv6_quoteb,
	      (int)tp->base.local_name.host.slen,
	      tp->base.local_name.host.ptr,
	      ipv6_quotee,
	      tp->base.local_name.port));


	return  PJ_SUCCESS;

on_error:
    qt_sip_transport_destroy(&tp);
	*ptp = nullptr;
    return status;


}

void qt_sip_transport_destroy(qt_sip_udp_transport **tp)
{
	(*tp)->socket->close();
	delete (*tp)->socket;
	(*tp) = nullptr;
}

pj_status_t udp_destroy(pjsip_transport *transport)
{
	qt_sip_udp_transport* tp = (qt_sip_udp_transport*)transport;
	qt_sip_transport_destroy(&tp);
	return PJ_SUCCESS;
}

pj_status_t udp_shutdown(pjsip_transport *transport)
{
	return pjsip_transport_dec_ref(transport);
}

pj_status_t udp_send_msg(pjsip_transport *transport,
						pjsip_tx_data *tdata,
						const pj_sockaddr_t *rem_addr,
						int addr_len,
						void *token,
						pjsip_transport_callback callback)
{
	struct qt_sip_udp_transport* tp = (struct qt_sip_udp_transport*)transport;
	pj_status_t status = PJ_SUCCESS;

	QByteArray msg(tdata->buf.start, tdata->buf.cur - tdata->buf.start);

	tp->socket->writeDatagram(msg, QHostAddress((sockaddr*)(&tdata->tp_info.dst_addr)), tdata->tp_info.dst_port);

	return status;
}

void init_rx_data(qt_sip_udp_transport* tp, pjsip_rx_data* rdata)
{
    /* Init tp_info part. */
    rdata->tp_info.pool = tp->base.pool;
    rdata->tp_info.transport = &tp->base;
	rdata->tp_info.tp_data = nullptr;
    rdata->tp_info.op_key.rdata = rdata;
}