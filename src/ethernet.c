
#include "ethernet.h"
#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // Step1: 数据长度检查
    if (buf->len < sizeof(ether_hdr_t)) {
        return; // 数据包不完整，丢弃
    }
    
    // Step2: 移除以太网包头并获取源MAC地址和协议类型
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    uint16_t protocol = swap16(hdr->protocol16); // 转换网络字节序为主机字节序
    uint8_t src_mac[NET_MAC_LEN];
    memcpy(src_mac, hdr->src, NET_MAC_LEN);
    buf_remove_header(buf, sizeof(ether_hdr_t));
    
    // Step3: 向上层传递数据包
    // printf("ETH:go up\n");
    net_in(buf, protocol, src_mac);
}

/**
 * @brief 处理一个要发送的数据包
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
    // Step1: 数据长度检查与填充
    if (buf->len < 46) {
        buf_add_padding(buf, 46 - buf->len);
    }
    
    // Step2: 添加以太网包头
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;
    
    // Step3: 填写目的MAC地址
    memcpy(hdr->dst, mac, NET_MAC_LEN);
    
    // Step4: 填写源MAC地址
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);
    
    // Step5: 填写协议类型
    hdr->protocol16 = swap16(protocol);
    
    // Step6: 发送数据帧
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**e
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
