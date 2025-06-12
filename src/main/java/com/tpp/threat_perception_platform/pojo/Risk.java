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
    private String desc;

    /**
     * 
     */
    private String type;

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
    public String getDesc() {
        return desc;
    }

    /**
     * 
     */
    public void setDesc(String desc) {
        this.desc = desc;
    }

    /**
     * 
     */
    public String getType() {
        return type;
    }

    /**
     * 
     */
    public void setType(String type) {
        this.type = type;
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
            && (this.getDesc() == null ? other.getDesc() == null : this.getDesc().equals(other.getDesc()))
            && (this.getType() == null ? other.getType() == null : this.getType().equals(other.getType()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getRe() == null) ? 0 : getRe().hashCode());
        result = prime * result + ((getDesc() == null) ? 0 : getDesc().hashCode());
        result = prime * result + ((getType() == null) ? 0 : getType().hashCode());
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
        sb.append(", desc=").append(desc);
        sb.append(", type=").append(type);
        sb.append("]");
        return sb.toString();
    }
}