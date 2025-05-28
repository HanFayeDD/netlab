#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // Step1: 检查数据包长度
    if (buf->len < sizeof(ip_hdr_t)) {
        return; // 数据包不完整，丢弃
    }

    // Step2: 进行报头检测
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    
    // 检查IP版本号是否为IPv4
    if (hdr->version != IP_VERSION_4) {
        return; // 不是IPv4，丢弃
    }
    
    // 计算IP头部长度(4字节为单位)
    uint16_t hdr_len = hdr->hdr_len * IP_HDR_LEN_PER_BYTE;
    if (hdr_len < sizeof(ip_hdr_t)) {
        return; // 头部长度异常，丢弃
    }
    
    // 检查总长度是否合法
    uint16_t total_len = swap16(hdr->total_len16);
    if (total_len > buf->len) {
        return; // 数据包不完整，丢弃
    }

    // Step3: 校验头部校验和
    uint16_t saved_checksum = hdr->hdr_checksum16; // 保存原始校验和
    hdr->hdr_checksum16 = 0; // 置零以便计算
    
    // 计算校验和并比较
    uint16_t computed_checksum = checksum16((uint16_t *)hdr, hdr_len);
    if (computed_checksum != saved_checksum) {
        hdr->hdr_checksum16 = saved_checksum; // 恢复原始校验和
        return; // 校验和错误，丢弃
    }
    hdr->hdr_checksum16 = saved_checksum; // 恢复原始校验和

    // Step4: 对比目的IP地址
    if (memcmp(hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        return; // 不是发给本机的包，丢弃
    }

    // Step5: 去除填充字段
    if (buf->len > total_len) {
        buf_remove_padding(buf, buf->len - total_len);
    }

    // Step6: 去掉IP报头
    buf_remove_header(buf, hdr_len);

    // Step7: 向上层传递数据包
    int res = net_in(buf, hdr->protocol, hdr->src_ip);
    
    if (res != 0) {
        // 协议不可达，发送ICMP错误
        // 先恢复IP头部
        buf_add_header(buf, hdr_len);
        memcpy(buf->data, hdr, hdr_len);
        
        // 发送ICMP协议不可达信息
        icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    // 1. 添加IP头部空间
    buf_add_header(buf, sizeof(ip_hdr_t));
    
    // 2. 填充IP头部字段
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    hdr->version = IP_VERSION_4;
    hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    hdr->tos = 0;  // 默认服务类型
    hdr->total_len16 = swap16(buf->len);  // 网络字节序
    
    // 设置分片相关字段
    hdr->id16 = swap16(id);
    hdr->flags_fragment16 = swap16(
        (mf ? IP_MORE_FRAGMENT : 0) |  // 设置MF标志位
        (offset & 0x1FFF)              // 设置分片偏移(13位)
    );
    
    hdr->ttl = 64;  // 默认TTL值
    hdr->protocol = protocol;
    hdr->hdr_checksum16 = 0;  // 先置零，后面计算
    
    // 设置IP地址
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);
    
    // 3. 计算校验和
    hdr->hdr_checksum16 = checksum16((uint16_t *)hdr, sizeof(ip_hdr_t));
    
    // 4. 调用ARP获取目标MAC地址并发送
    arp_out(buf, ip);
}


/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    // IP头部长度
    const uint16_t ip_hdr_len = sizeof(ip_hdr_t);
    // 最大传输单元(MTU) - IP头部 = 最大负载长度
    const uint16_t max_payload_len = 1500 - ip_hdr_len;
    
    // Step1: 检查数据报包长是否超过最大负载
    if (buf->len > max_payload_len) {
        // Step2: 需要分片处理
        uint16_t remaining_len = buf->len;
        uint16_t offset = 0;
        static uint16_t identification = 0; // 数据包ID(简单实现，实际应该更复杂)
        
        // 处理所有完整的分片
        while (remaining_len > max_payload_len) {
            buf_t ip_buf;
            buf_init(&ip_buf, max_payload_len);
            
            // 复制数据到分片
            memcpy(ip_buf.data, buf->data + offset, max_payload_len);
            
            // 发送分片(MF=1表示还有更多分片)
            ip_fragment_out(&ip_buf, ip, protocol, identification, 
                           offset / IP_HDR_OFFSET_PER_BYTE, 1);
            
            offset += max_payload_len;
            remaining_len -= max_payload_len;
        }
        
        // 处理最后一个分片(MF=0)
        if (remaining_len > 0) {
            buf_t ip_buf;
            buf_init(&ip_buf, remaining_len);
            
            // 复制数据到分片
            memcpy(ip_buf.data, buf->data + offset, remaining_len);
            
            // 发送最后一个分片
            ip_fragment_out(&ip_buf, ip, protocol, identification, 
                           offset / IP_HDR_OFFSET_PER_BYTE, 0);
        }
        
        identification++; // 递增ID
    } else {
        // Step3: 不需要分片，直接发送
        ip_fragment_out(buf, ip, protocol, 0, 0, 0);
    }
}


/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}