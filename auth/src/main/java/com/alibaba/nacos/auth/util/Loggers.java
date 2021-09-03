package com.alibaba.nacos.auth.util;

import ch.qos.logback.classic.Level;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Loggers {
    
    public static final Logger AUTH = LoggerFactory.getLogger("com.alibaba.nacos.core.auth");
    
    public static final Logger CORE = LoggerFactory.getLogger("com.alibaba.nacos.core");
    
    public static final Logger RAFT = LoggerFactory.getLogger("com.alibaba.nacos.core.protocol.raft");
    
    public static final Logger DISTRO = LoggerFactory.getLogger("com.alibaba.nacos.core.protocol.distro");
    
    public static final Logger CLUSTER = LoggerFactory.getLogger("com.alibaba.nacos.core.cluster");
    
    public static final Logger REMOTE = LoggerFactory.getLogger("com.alibaba.nacos.core.remote");
    
    public static final Logger REMOTE_PUSH = LoggerFactory.getLogger("com.alibaba.nacos.core.remote.push");
    
    public static final Logger REMOTE_DIGEST = LoggerFactory.getLogger("com.alibaba.nacos.core.remote.digest");
    
    public static final Logger TPS_CONTROL_DIGEST = LoggerFactory
            .getLogger("com.alibaba.nacos.core.remote.control.digest");
    
    public static final Logger TPS_CONTROL = LoggerFactory.getLogger("com.alibaba.nacos.core.remote.control");
    
    public static final Logger TPS_CONTROL_DETAIL = LoggerFactory.getLogger("com.alibaba.nacos.core.remote.control.detail");
    
    public static void setLogLevel(String logName, String level) {
        
        switch (logName) {
            case "core-auth":
                ((ch.qos.logback.classic.Logger) AUTH).setLevel(Level.valueOf(level));
                break;
            case "core":
                ((ch.qos.logback.classic.Logger) CORE).setLevel(Level.valueOf(level));
                break;
            case "core-raft":
                ((ch.qos.logback.classic.Logger) RAFT).setLevel(Level.valueOf(level));
                break;
            case "core-distro":
                ((ch.qos.logback.classic.Logger) DISTRO).setLevel(Level.valueOf(level));
                break;
            case "core-cluster":
                ((ch.qos.logback.classic.Logger) CLUSTER).setLevel(Level.valueOf(level));
                break;
            default:
                break;
        }
        
    }
}
