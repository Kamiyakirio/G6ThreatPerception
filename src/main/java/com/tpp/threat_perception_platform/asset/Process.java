package com.tpp.threat_perception_platform.asset;

import java.util.Date;

/**
 * 
 * @TableName process
 */
public class Process {
    /**
     * 用于唯一标识进程，和进程本身信息无关
     */
    private Long processId;

    /**
     * 进程id
     */
    private Integer pid;

    /**
     * 父进程id
     */
    private Integer ppid;

    /**
     * 
     */
    private String name;

    /**
     * 
     */
    private String cmd;

    /**
     * 优先级
     */
    private Integer priority;

    /**
     * 描述
     */
    private String description;

    /**
     * 
     */
    private String hostName;

    /**
     * 
     */
    private Integer id;

    /**
     * 
     */
    private String macAddress;

    /**
     * 
     */
    private Date time;

    /**
     * 区分每次扫描
     */
    private Integer detectId;

    /**
     * 用于唯一标识进程，和进程本身信息无关
     */
    public Long getProcessId() {
        return processId;
    }

    /**
     * 用于唯一标识进程，和进程本身信息无关
     */
    public void setProcessId(Long processId) {
        this.processId = processId;
    }

    /**
     * 进程id
     */
    public Integer getPid() {
        return pid;
    }

    /**
     * 进程id
     */
    public void setPid(Integer pid) {
        this.pid = pid;
    }

    /**
     * 父进程id
     */
    public Integer getPpid() {
        return ppid;
    }

    /**
     * 父进程id
     */
    public void setPpid(Integer ppid) {
        this.ppid = ppid;
    }

    /**
     * 
     */
    public String getName() {
        return name;
    }

    /**
     * 
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * 
     */
    public String getCmd() {
        return cmd;
    }

    /**
     * 
     */
    public void setCmd(String cmd) {
        this.cmd = cmd;
    }

    /**
     * 优先级
     */
    public Integer getPriority() {
        return priority;
    }

    /**
     * 优先级
     */
    public void setPriority(Integer priority) {
        this.priority = priority;
    }

    /**
     * 描述
     */
    public String getDescription() {
        return description;
    }

    /**
     * 描述
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * 
     */
    public String getHostName() {
        return hostName;
    }

    /**
     * 
     */
    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

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
    public String getMacAddress() {
        return macAddress;
    }

    /**
     * 
     */
    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    /**
     * 
     */
    public Date getTime() {
        return time;
    }

    /**
     * 
     */
    public void setTime(Date time) {
        this.time = time;
    }

    /**
     * 区分每次扫描
     */
    public Integer getDetectId() {
        return detectId;
    }

    /**
     * 区分每次扫描
     */
    public void setDetectId(Integer detectId) {
        this.detectId = detectId;
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
        Process other = (Process) that;
        return (this.getProcessId() == null ? other.getProcessId() == null : this.getProcessId().equals(other.getProcessId()))
            && (this.getPid() == null ? other.getPid() == null : this.getPid().equals(other.getPid()))
            && (this.getPpid() == null ? other.getPpid() == null : this.getPpid().equals(other.getPpid()))
            && (this.getName() == null ? other.getName() == null : this.getName().equals(other.getName()))
            && (this.getCmd() == null ? other.getCmd() == null : this.getCmd().equals(other.getCmd()))
            && (this.getPriority() == null ? other.getPriority() == null : this.getPriority().equals(other.getPriority()))
            && (this.getDescription() == null ? other.getDescription() == null : this.getDescription().equals(other.getDescription()))
            && (this.getHostName() == null ? other.getHostName() == null : this.getHostName().equals(other.getHostName()))
            && (this.getId() == null ? other.getId() == null : this.getId().equals(other.getId()))
            && (this.getMacAddress() == null ? other.getMacAddress() == null : this.getMacAddress().equals(other.getMacAddress()))
            && (this.getTime() == null ? other.getTime() == null : this.getTime().equals(other.getTime()))
            && (this.getDetectId() == null ? other.getDetectId() == null : this.getDetectId().equals(other.getDetectId()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getProcessId() == null) ? 0 : getProcessId().hashCode());
        result = prime * result + ((getPid() == null) ? 0 : getPid().hashCode());
        result = prime * result + ((getPpid() == null) ? 0 : getPpid().hashCode());
        result = prime * result + ((getName() == null) ? 0 : getName().hashCode());
        result = prime * result + ((getCmd() == null) ? 0 : getCmd().hashCode());
        result = prime * result + ((getPriority() == null) ? 0 : getPriority().hashCode());
        result = prime * result + ((getDescription() == null) ? 0 : getDescription().hashCode());
        result = prime * result + ((getHostName() == null) ? 0 : getHostName().hashCode());
        result = prime * result + ((getId() == null) ? 0 : getId().hashCode());
        result = prime * result + ((getMacAddress() == null) ? 0 : getMacAddress().hashCode());
        result = prime * result + ((getTime() == null) ? 0 : getTime().hashCode());
        result = prime * result + ((getDetectId() == null) ? 0 : getDetectId().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", processId=").append(processId);
        sb.append(", pid=").append(pid);
        sb.append(", ppid=").append(ppid);
        sb.append(", name=").append(name);
        sb.append(", cmd=").append(cmd);
        sb.append(", priority=").append(priority);
        sb.append(", description=").append(description);
        sb.append(", hostName=").append(hostName);
        sb.append(", id=").append(id);
        sb.append(", macAddress=").append(macAddress);
        sb.append(", time=").append(time);
        sb.append(", detectId=").append(detectId);
        sb.append("]");
        return sb.toString();
    }
}