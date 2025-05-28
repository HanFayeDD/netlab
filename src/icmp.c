#include "icmp.h"

#include "ip.h"
#include "net.h"


#define ICMP_HDR_LEN sizeof(icmp_hdr_t)
#define ICMP_UNREACH_DATA_LEN (sizeof(ip_hdr_t) + 8)
/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // TO-DO
     // Step1: 初始化并封装数据
    buf_t txbuf;
    buf_init(&txbuf, req_buf->len);
    
    // 复制整个ICMP报文(包括头部和数据)
    memcpy(txbuf.data, req_buf->data, req_buf->len);
    
    icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;
    // 修改类型为回显应答
    hdr->type = ICMP_TYPE_ECHO_REPLY;
    
    // Step2: 填写校验和
    hdr->checksum16 = 0;
    hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    
    // Step3: 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // TO-DO
        // Step1: 报头检测
    if (buf->len < ICMP_HDR_LEN) {
        return;  // 数据包不完整，丢弃
    }
    
    icmp_hdr_t *hdr = (icmp_hdr_t *)buf->data;
    
    // Step2: 查看ICMP类型
    if (hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        // Step3: 回送回显应答
        icmp_resp(buf, src_ip);
    }
    // 其他类型的ICMP报文暂不处理
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // TO-DO
    // Step1: 初始化并填写报头
    buf_t txbuf;
    // ICMP头部 + 原始IP头+8字节数据
    buf_init(&txbuf, ICMP_HDR_LEN + ICMP_UNREACH_DATA_LEN);
    
    icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;
    hdr->type = ICMP_TYPE_UNREACH;
    hdr->code = code;
    hdr->checksum16 = 0;
    hdr->id16 = 0;
    hdr->seq16 = 0;
    
    // Step2: 填写数据与校验和
    // 复制原始IP头+8字节数据
    size_t copy_len = (recv_buf->len < ICMP_UNREACH_DATA_LEN) ? 
                      recv_buf->len : ICMP_UNREACH_DATA_LEN;
    memcpy(txbuf.data + ICMP_HDR_LEN, recv_buf->data, copy_len);
    
    // 计算校验和
    hdr->checksum16 = checksum16((uint16_t *)txbuf.data, txbuf.len);
    
    // Step3: 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}