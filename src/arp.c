#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    // TO-DO
    //初始化缓冲区
    buf_init(&txbuf, sizeof(arp_pkt_t));

    //填写ARP报头
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    *arp_pkt = arp_init_pkt;//将预先定义好的报头复制进data字段

    //设置目标IP地址
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);

    //协议类型
    arp_pkt->opcode16 = swap16(ARP_REQUEST);

    //发送arp报文
    uint8_t broadcast_mac[NET_MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ethernet_out(&txbuf, broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // TO-DO
    //初始化缓冲区
    buf_init(&txbuf, sizeof(arp_pkt_t));

    //填写报文首部
    arp_pkt_t *arp_pkt = (arp_pkt_t *)txbuf.data;
    *arp_pkt = arp_init_pkt;

    //设置操作码
    arp_pkt->opcode16 = swap16(ARP_REPLY);

    //设置arp请求发起方的IP和MAC信息
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(arp_pkt->target_mac, target_mac, NET_MAC_LEN);

    //设置本机mac
    memcpy(arp_pkt->sender_mac, net_if_mac, NET_MAC_LEN);

    //发送arp回复报文
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    //检查数据长度
    if (buf->len < sizeof(arp_pkt_t)){
        return;
    }
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    //报头检查
    if (swap16(arp_pkt->hw_type16) != ARP_HW_ETHER || 
    swap16(arp_pkt->pro_type16) != NET_PROTOCOL_IP ||
    arp_pkt->hw_len != NET_MAC_LEN || 
    arp_pkt->pro_len != NET_IP_LEN) {
        return;
    }
    //更新arp表项目
    uint16_t opcode = swap16(arp_pkt->opcode16);
    //更新ip-mac表
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);
    //更细ip-缓存表
    buf_t *cached_buf = map_get(&arp_buf, arp_pkt->sender_ip);
    if (cached_buf != NULL){
        //有缓存
        //收到的是ARP回复
        if (opcode == ARP_REPLY){
            // 发送已有mac的数据包
            ethernet_out(cached_buf, arp_pkt->sender_mac, NET_PROTOCOL_IP);
            // 删除缓存
            map_delete(&arp_buf, arp_pkt->sender_ip);
        }
    } else {
        //无缓存的情况
        // 判断是否是请求本机的mac地址
        if (opcode == ARP_REQUEST && memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0){
            arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // TO-DO
    //查找arp表
    uint8_t *mac = map_get(&arp_table, ip);
    //找到对应项目
    if (mac != NULL){
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    } else {
        //未找到对应项目
        buf_t *cached_buf = map_get(&arp_buf, ip);
        if (cached_buf == NULL) {
            //没有正在等待的arp请求
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}