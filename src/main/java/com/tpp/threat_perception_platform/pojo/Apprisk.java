package com.tpp.threat_perception_platform.pojo;

/**
 * 
 * @TableName apprisk
 */
public class Apprisk {
    /**
     * 自增ID
     */
    private Integer id;

    /**
     * 应用风险名字
     */
    private String appriskName;

    /**
     * 风险描述
     */
    private String appriskDesc;

    /**
     * 漏洞等级: 1 高危 2中危 3低危
     */
    private Integer appriskLevel;

    /**
     * 请求类型:GET/POST/PUT/DELETE
     */
    private String appriskRequestType;

    /**
     * 漏洞类型: SQL注入/反序列化
     */
    private String appriskType;

    /**
     * 漏洞产生的路径
     */
    private String appriskPath;

    /**
     * 漏洞攻击载荷
     */
    private String appriskPayload;

    /**
     * 漏洞的验证标记
     */
    private String appriskFlag;

    /**
     * 自增ID
     */
    public Integer getId() {
        return id;
    }

    /**
     * 自增ID
     */
    public void setId(Integer id) {
        this.id = id;
    }

    /**
     * 应用风险名字
     */
    public String getAppriskName() {
        return appriskName;
    }

    /**
     * 应用风险名字
     */
    public void setAppriskName(String appriskName) {
        this.appriskName = appriskName;
    }

    /**
     * 风险描述
     */
    public String getAppriskDesc() {
        return appriskDesc;
    }

    /**
     * 风险描述
     */
    public void setAppriskDesc(String appriskDesc) {
        this.appriskDesc = appriskDesc;
    }

    /**
     * 漏洞等级: 1 高危 2中危 3低危
     */
    public Integer getAppriskLevel() {
        return appriskLevel;
    }

    /**
     * 漏洞等级: 1 高危 2中危 3低危
     */
    public void setAppriskLevel(Integer appriskLevel) {
        this.appriskLevel = appriskLevel;
    }

    /**
     * 请求类型:GET/POST/PUT/DELETE
     */
    public String getAppriskRequestType() {
        return appriskRequestType;
    }

    /**
     * 请求类型:GET/POST/PUT/DELETE
     */
    public void setAppriskRequestType(String appriskRequestType) {
        this.appriskRequestType = appriskRequestType;
    }

    /**
     * 漏洞类型: SQL注入/反序列化
     */
    public String getAppriskType() {
        return appriskType;
    }

    /**
     * 漏洞类型: SQL注入/反序列化
     */
    public void setAppriskType(String appriskType) {
        this.appriskType = appriskType;
    }

    /**
     * 漏洞产生的路径
     */
    public String getAppriskPath() {
        return appriskPath;
    }

    /**
     * 漏洞产生的路径
     */
    public void setAppriskPath(String appriskPath) {
        this.appriskPath = appriskPath;
    }

    /**
     * 漏洞攻击载荷
     */
    public String getAppriskPayload() {
        return appriskPayload;
    }

    /**
     * 漏洞攻击载荷
     */
    public void setAppriskPayload(String appriskPayload) {
        this.appriskPayload = appriskPayload;
    }

    /**
     * 漏洞的验证标记
     */
    public String getAppriskFlag() {
        return appriskFlag;
    }

    /**
     * 漏洞的验证标记
     */
    public void setAppriskFlag(String appriskFlag) {
        this.appriskFlag = appriskFlag;
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
        Apprisk other = (Apprisk) that;
        return (this.getId() == null ? other.getId() == null : this.getId().equals(other.getId()))
            && (this.getAppriskName() == null ? other.getAppriskName() == null : this.getAppriskName().equals(other.getAppriskName()))
            && (this.getAppriskDesc() == null ? other.getAppriskDesc() == null : this.getAppriskDesc().equals(other.getAppriskDesc()))
            && (this.getAppriskLevel() == null ? other.getAppriskLevel() == null : this.getAppriskLevel().equals(other.getAppriskLevel()))
            && (this.getAppriskRequestType() == null ? other.getAppriskRequestType() == null : this.getAppriskRequestType().equals(other.getAppriskRequestType()))
            && (this.getAppriskType() == null ? other.getAppriskType() == null : this.getAppriskType().equals(other.getAppriskType()))
            && (this.getAppriskPath() == null ? other.getAppriskPath() == null : this.getAppriskPath().equals(other.getAppriskPath()))
            && (this.getAppriskPayload() == null ? other.getAppriskPayload() == null : this.getAppriskPayload().equals(other.getAppriskPayload()))
            && (this.getAppriskFlag() == null ? other.getAppriskFlag() == null : this.getAppriskFlag().equals(other.getAppriskFlag()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getAppriskName() == null) ? 0 : getAppriskName().hashCode());
        result = prime * result + ((getAppriskDesc() == null) ? 0 : getAppriskDesc().hashCode());
        result = prime * result + ((getAppriskLevel() == null) ? 0 : getAppriskLevel().hashCode());
        result = prime * result + ((getAppriskRequestType() == null) ? 0 : getAppriskRequestType().hashCode());
        result = prime * result + ((getAppriskType() == null) ? 0 : getAppriskType().hashCode());
        result = prime * result + ((getAppriskPath() == null) ? 0 : getAppriskPath().hashCode());
        result = prime * result + ((getAppriskPayload() == null) ? 0 : getAppriskPayload().hashCode());
        result = prime * result + ((getAppriskFlag() == null) ? 0 : getAppriskFlag().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", id=").append(id);
        sb.append(", appriskName=").append(appriskName);
        sb.append(", appriskDesc=").append(appriskDesc);
        sb.append(", appriskLevel=").append(appriskLevel);
        sb.append(", appriskRequestType=").append(appriskRequestType);
        sb.append(", appriskType=").append(appriskType);
        sb.append(", appriskPath=").append(appriskPath);
        sb.append(", appriskPayload=").append(appriskPayload);
        sb.append(", appriskFlag=").append(appriskFlag);
        sb.append("]");
        return sb.toString();
    }
}