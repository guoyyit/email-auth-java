package com.github.guoyyit.emailauthjava.dns;

/**
 * 可注入的本地 DNS 解析接口，不依赖真实网络。
 * 实现必须保证三类故障可区分：NXDOMAIN、TIMEOUT、MALFORMED。
 */
public interface DnsResolver {

    /**
     * 查询给定名称与类型。永不返回 null；故障以对应 {@link DnsStatus} 返回。
     */
    DnsAnswer query(String name, RecordType type);
}
