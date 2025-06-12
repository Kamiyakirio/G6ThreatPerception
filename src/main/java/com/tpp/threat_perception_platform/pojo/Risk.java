package com.tpp.threat_perception_platform.pojo;

/**
 * 
 * @TableName risk
 */
public class Risk {
    /**
     * 
     */
    private Integer id;

    /**
     * 
     */
    private String re;

    /**
     * 
     */
    private String riskDesc;

    /**
     * 
     */
    private String riskType;

    /**
     * 
     */
    public Integer getId() {
        return id;
    }

    /**
     * 
     */
    public void setId(Integer id) {
        this.id = id;
    }

    /**
     * 
     */
    public String getRe() {
        return re;
    }

    /**
     * 
     */
    public void setRe(String re) {
        this.re = re;
    }

    /**
     * 
     */
    public String getRiskDesc() {
        return riskDesc;
    }

    /**
     * 
     */
    public void setRiskDesc(String riskDesc) {
        this.riskDesc = riskDesc;
    }

    /**
     * 
     */
    public String getRiskType() {
        return riskType;
    }

    /**
     * 
     */
    public void setRiskType(String riskType) {
        this.riskType = riskType;
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
        Risk other = (Risk) that;
        return (this.getId() == null ? other.getId() == null : this.getId().equals(other.getId()))
            && (this.getRe() == null ? other.getRe() == null : this.getRe().equals(other.getRe()))
            && (this.getRiskDesc() == null ? other.getRiskDesc() == null : this.getRiskDesc().equals(other.getRiskDesc()))
            && (this.getRiskType() == null ? other.getRiskType() == null : this.getRiskType().equals(other.getRiskType()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getRe() == null) ? 0 : getRe().hashCode());
        result = prime * result + ((getRiskDesc() == null) ? 0 : getRiskDesc().hashCode());
        result = prime * result + ((getRiskType() == null) ? 0 : getRiskType().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", id=").append(id);
        sb.append(", re=").append(re);
        sb.append(", riskDesc=").append(riskDesc);
        sb.append(", riskType=").append(riskType);
        sb.append("]");
        return sb.toString();
    }
}