package com.tpp.threat_perception_platform.pojo;

import java.math.BigDecimal;
import java.util.Date;

/**
 * 主机补丁扫描结果表
 * @TableName hotfix_result
 */
public class HotfixResult {
    /**
     * 自增主键
     */
    private Long id;

    /**
     * 主机MAC地址，格式XX:XX:XX:XX:XX:XX
     */
    private String macAddress;

    /**
     * Windows补丁号，如KB5005565
     */
    private String kbId;

    /**
     * CVE漏洞编号，如CVE-2023-1234
     */
    private String cveId;

    /**
     * CVSS漏洞评分，范围0.0-10.0
     */
    private BigDecimal score;

    /**
     * 微软安全响应文档ID，如CVRF-2023-123
     */
    private String cvrfId;

    /**
     * 产品ID，与win_product_name表关联
     */
    private String productId;

    /**
     * 产品名称，冗余存储便于查询
     */
    private String productName;

    /**
     * 数据日期，格式YYYY-MM-DD
     */
    private Date dt;

    /**
     * 自增主键
     */
    public Long getId() {
        return id;
    }

    /**
     * 自增主键
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * 主机MAC地址，格式XX:XX:XX:XX:XX:XX
     */
    public String getMacAddress() {
        return macAddress;
    }

    /**
     * 主机MAC地址，格式XX:XX:XX:XX:XX:XX
     */
    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    /**
     * Windows补丁号，如KB5005565
     */
    public String getKbId() {
        return kbId;
    }

    /**
     * Windows补丁号，如KB5005565
     */
    public void setKbId(String kbId) {
        this.kbId = kbId;
    }

    /**
     * CVE漏洞编号，如CVE-2023-1234
     */
    public String getCveId() {
        return cveId;
    }

    /**
     * CVE漏洞编号，如CVE-2023-1234
     */
    public void setCveId(String cveId) {
        this.cveId = cveId;
    }

    /**
     * CVSS漏洞评分，范围0.0-10.0
     */
    public BigDecimal getScore() {
        return score;
    }

    /**
     * CVSS漏洞评分，范围0.0-10.0
     */
    public void setScore(BigDecimal score) {
        this.score = score;
    }

    /**
     * 微软安全响应文档ID，如CVRF-2023-123
     */
    public String getCvrfId() {
        return cvrfId;
    }

    /**
     * 微软安全响应文档ID，如CVRF-2023-123
     */
    public void setCvrfId(String cvrfId) {
        this.cvrfId = cvrfId;
    }

    /**
     * 产品ID，与win_product_name表关联
     */
    public String getProductId() {
        return productId;
    }

    /**
     * 产品ID，与win_product_name表关联
     */
    public void setProductId(String productId) {
        this.productId = productId;
    }

    /**
     * 产品名称，冗余存储便于查询
     */
    public String getProductName() {
        return productName;
    }

    /**
     * 产品名称，冗余存储便于查询
     */
    public void setProductName(String productName) {
        this.productName = productName;
    }

    /**
     * 数据日期，格式YYYY-MM-DD
     */
    public Date getDt() {
        return dt;
    }

    /**
     * 数据日期，格式YYYY-MM-DD
     */
    public void setDt(Date dt) {
        this.dt = dt;
    }

    @Override
    public boolean equals(Object that) {
        if (this == that) {
            return true;
        }
        if (that == null) {
            return false;
        }
        if (getClass() != that.getClass()) {
            return false;
        }
        HotfixResult other = (HotfixResult) that;
        return (this.getId() == null ? other.getId() == null : this.getId().equals(other.getId()))
            && (this.getMacAddress() == null ? other.getMacAddress() == null : this.getMacAddress().equals(other.getMacAddress()))
            && (this.getKbId() == null ? other.getKbId() == null : this.getKbId().equals(other.getKbId()))
            && (this.getCveId() == null ? other.getCveId() == null : this.getCveId().equals(other.getCveId()))
            && (this.getScore() == null ? other.getScore() == null : this.getScore().equals(other.getScore()))
            && (this.getCvrfId() == null ? other.getCvrfId() == null : this.getCvrfId().equals(other.getCvrfId()))
            && (this.getProductId() == null ? other.getProductId() == null : this.getProductId().equals(other.getProductId()))
            && (this.getProductName() == null ? other.getProductName() == null : this.getProductName().equals(other.getProductName()))
            && (this.getDt() == null ? other.getDt() == null : this.getDt().equals(other.getDt()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getMacAddress() == null) ? 0 : getMacAddress().hashCode());
        result = prime * result + ((getKbId() == null) ? 0 : getKbId().hashCode());
        result = prime * result + ((getCveId() == null) ? 0 : getCveId().hashCode());
        result = prime * result + ((getScore() == null) ? 0 : getScore().hashCode());
        result = prime * result + ((getCvrfId() == null) ? 0 : getCvrfId().hashCode());
        result = prime * result + ((getProductId() == null) ? 0 : getProductId().hashCode());
        result = prime * result + ((getProductName() == null) ? 0 : getProductName().hashCode());
        result = prime * result + ((getDt() == null) ? 0 : getDt().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", id=").append(id);
        sb.append(", macAddress=").append(macAddress);
        sb.append(", kbId=").append(kbId);
        sb.append(", cveId=").append(cveId);
        sb.append(", score=").append(score);
        sb.append(", cvrfId=").append(cvrfId);
        sb.append(", productId=").append(productId);
        sb.append(", productName=").append(productName);
        sb.append(", dt=").append(dt);
        sb.append("]");
        return sb.toString();
    }
}