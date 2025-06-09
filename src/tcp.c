#include "tcp.h"
#include "icmp.h"
#include "ip.h"
#include <assert.h>
#include <stdbool.h>

map_t tcp_handler_table;  // dst-port -> handler
static map_t tcp_conn_table;  // [src_ip, src_port, dst_port] -> tcp_conn

/* =============================== TOOLS =============================== */

size_t bytes_in_flight(size_t len, uint8_t flags) {
    size_t res = len;
    if (TCP_FLG_ISSET(flags, TCP_FLG_SYN))
        res += 1;
    if (TCP_FLG_ISSET(flags, TCP_FLG_FIN))
        res += 1;
    return res;
}

static inline uint32_t tcp_generate_initial_seq() {
    return rand() % UINT32_MAX;
}

void tcp_rst(tcp_conn_t *tcp_conn) {
    memset(tcp_conn, 0, sizeof(tcp_conn_t));
    tcp_conn->state = TCP_STATE_LISTEN;
}

static inline tcp_key_t generate_tcp_key(uint8_t remote_ip[NET_IP_LEN], uint16_t remote_port, uint16_t host_port) {
    tcp_key_t key;
    memcpy(key.remote_ip, remote_ip, NET_IP_LEN);
    key.remote_port = remote_port;
    key.host_port = host_port;
    return key;
}

static inline tcp_conn_t *tcp_get_connection(uint8_t remote_ip[NET_IP_LEN], uint16_t remote_port, uint16_t host_port, uint8_t create_if_missing) {
    tcp_key_t key = generate_tcp_key(remote_ip, remote_port, host_port);
    tcp_conn_t *tcp_conn = map_get(&tcp_conn_table, &key);
    if (!tcp_conn && create_if_missing) {
        tcp_conn_t new_conn;
        tcp_rst(&new_conn);
        map_set(&tcp_conn_table, &key, &new_conn);
        tcp_conn = map_get(&tcp_conn_table, &key);
    }
    return tcp_conn;
}

static inline void tcp_close_connection(uint8_t remote_ip[NET_IP_LEN], uint16_t remote_port, uint16_t host_port) {
    tcp_key_t key = generate_tcp_key(remote_ip, remote_port, host_port);
    map_delete(&tcp_conn_table, &key);
}

/* =============================== TOOLS =============================== */

/* =============================== COMMON API =============================== */

void tcp_out(tcp_conn_t *tcp_conn, buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port, uint8_t flags) {
    buf_add_header(buf, sizeof(tcp_hdr_t));
    
    tcp_hdr_t *hdr = (tcp_hdr_t *)buf->data;
    hdr->src_port16 = swap16(src_port);
    hdr->dst_port16 = swap16(dst_port);
    hdr->seq = swap32(tcp_conn->seq);
    hdr->ack = swap32(tcp_conn->ack);
    hdr->doff = (sizeof(tcp_hdr_t) / 4) << 4;
    hdr->flags = flags;
    hdr->win = swap16(TCP_MAX_WINDOW_SIZE);
    hdr->uptr = 0;
    hdr->checksum16 = 0;
    
    hdr->checksum16 = transport_checksum(NET_PROTOCOL_TCP, buf, net_if_ip, dst_ip);
    
    ip_out(buf, dst_ip, NET_PROTOCOL_TCP);
}

void tcp_in(buf_t *buf, uint8_t *src_ip) {
    if (buf->len < sizeof(tcp_hdr_t))
        return;

    tcp_hdr_t *hdr = (tcp_hdr_t *)buf->data;

    uint16_t checksum = hdr->checksum16;
    hdr->checksum16 = 0;
    if (transport_checksum(NET_PROTOCOL_TCP, buf, src_ip, net_if_ip) != checksum)
        return;

    uint8_t *remote_ip = src_ip;
    uint16_t remote_port = swap16(hdr->src_port16);
    uint16_t host_port = swap16(hdr->dst_port16);
    tcp_conn_t *tcp_conn = tcp_get_connection(remote_ip, remote_port, host_port, true);

    uint8_t recv_flags = hdr->flags;
    if (TCP_FLG_ISSET(recv_flags, TCP_FLG_RST)) {
        tcp_close_connection(remote_ip, remote_port, host_port);
        return;
    }

    uint32_t remote_seq = swap32(hdr->seq);
    uint32_t remote_ack = swap32(hdr->ack);
    uint8_t send_flags = 0;
    buf_t txbuf;

    switch (tcp_conn->state) {
        case TCP_STATE_LISTEN:
            if (!TCP_FLG_ISSET(recv_flags, TCP_FLG_SYN))
                return;

            tcp_conn->seq = tcp_generate_initial_seq();
            tcp_conn->ack = remote_seq + 1;
            send_flags = TCP_FLG_SYN | TCP_FLG_ACK;
            tcp_conn->state = TCP_STATE_SYN_RECEIVED;
            
            buf_init(&txbuf, 0);
            tcp_out(tcp_conn, &txbuf, host_port, remote_ip, remote_port, send_flags);
            tcp_conn->seq += 1; // SYN consumes one sequence number
            break;

        case TCP_STATE_SYN_RECEIVED:
            if (!TCP_FLG_ISSET(recv_flags, TCP_FLG_ACK))
                return;
                
            tcp_conn->state = TCP_STATE_ESTABLISHED;
            break;

        case TCP_STATE_ESTABLISHED:
            if (remote_seq != tcp_conn->ack) {
                // Out-of-order packet, send duplicate ACK
                buf_init(&txbuf, 0);
                tcp_out(tcp_conn, &txbuf, host_port, remote_ip, remote_port, TCP_FLG_ACK);
                return;
            }

            size_t data_len = buf->len - sizeof(tcp_hdr_t);
            if (data_len > 0) {
                tcp_conn->ack = remote_seq + data_len;
                send_flags = TCP_FLG_ACK;
                
                tcp_handler_t *handler = map_get(&tcp_handler_table, &host_port);
                if (handler == NULL) {
                    buf_add_header(buf, sizeof(tcp_hdr_t));
                    icmp_unreachable(buf, remote_ip, ICMP_CODE_PORT_UNREACH);
                    return;
                }
                
                buf_remove_header(buf, sizeof(tcp_hdr_t));
                (*handler)(tcp_conn, buf->data, data_len, remote_ip, remote_port);
            }

            if (TCP_FLG_ISSET(recv_flags, TCP_FLG_FIN)) {
                tcp_conn->ack += 1;
                send_flags = TCP_FLG_ACK;
                tcp_conn->state = TCP_STATE_CLOSE_WAIT;
                
                buf_init(&txbuf, 0);
                tcp_out(tcp_conn, &txbuf, host_port, remote_ip, remote_port, send_flags);
                
                // // 应用程序关闭连接后，发送FIN包（第三次挥手）
                //注释掉AB两部分即可正常通过自动测试，但是四次挥手只有两次
                //A
                send_flags = TCP_FLG_FIN | TCP_FLG_ACK;
                tcp_conn->state = TCP_STATE_LAST_ACK;
                buf_init(&txbuf, 0);
                tcp_out(tcp_conn, &txbuf, host_port, remote_ip, remote_port, send_flags);
                tcp_conn->seq += 1; // FIN consumes one sequence number
                printf("sending FIN from server\n");
                //A
            }
            break;

        case TCP_STATE_CLOSE_WAIT:
            // 应用程序关闭连接后，发送FIN包（第三次挥手）
            //B
            send_flags = TCP_FLG_FIN | TCP_FLG_ACK;
            tcp_conn->state = TCP_STATE_LAST_ACK;
            buf_init(&txbuf, 0);
            tcp_out(tcp_conn, &txbuf, host_port, remote_ip, remote_port, send_flags);
            tcp_conn->seq += 1; // FIN consumes one sequence number
            //B
            break;

        case TCP_STATE_LAST_ACK:
            if (!TCP_FLG_ISSET(recv_flags, TCP_FLG_ACK))
                return;
            tcp_close_connection(remote_ip, remote_port, host_port);
            break;

        default:
            printf("Unsupported state %d\n", tcp_conn->state);
            break;
    }
}

void tcp_send(tcp_conn_t *tcp_conn, uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port) {
    if (len > TCP_MAX_WINDOW_SIZE) {
        printf("Package is too big [max=%d, current=%d]\n", TCP_MAX_WINDOW_SIZE, len);
        return;
    }
    if (len == 0) {
        printf("No payload to send\n");
        return;
    }

    buf_t tx_buf;
    buf_init(&tx_buf, len);
    if (data)
        memcpy(tx_buf.data, data, len);
    tcp_out(tcp_conn, &tx_buf, src_port, dst_ip, dst_port, TCP_FLG_ACK);

    tcp_conn->seq += len;
    tcp_conn->not_send_empty_ack = 1;
}

void tcp_init() {
    map_init(&tcp_handler_table, sizeof(uint16_t), sizeof(tcp_handler_t), 0, 0, NULL, NULL);
    map_init(&tcp_conn_table, sizeof(tcp_key_t), sizeof(tcp_conn_t), 0, 0, NULL, NULL);
    net_add_protocol(NET_PROTOCOL_TCP, tcp_in);
    srand(time(NULL));
}

int tcp_open(uint16_t port, tcp_handler_t handler) {
    return map_set(&tcp_handler_table, &port, &handler);
}

static _Thread_local uint16_t close_port;
static void close_port_fn(void *key, void *value, time_t *timestamp) {
    tcp_key_t *tcp_key = key;
    if (tcp_key->host_port == close_port) {
        map_delete(&tcp_conn_table, key);
    }
}

void tcp_close(uint16_t port) {
    close_port = port;
    map_foreach(&tcp_conn_table, close_port_fn);
    map_delete(&tcp_handler_table, &port);
}