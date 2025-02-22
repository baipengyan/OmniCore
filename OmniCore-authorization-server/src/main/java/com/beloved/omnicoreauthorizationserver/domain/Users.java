package com.beloved.omnicoreauthorizationserver.domain;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * @author baipengyan
 */
@Data
@TableName(value = "users")
public class Users {
    @TableId(value = "username", type = IdType.INPUT)
    private String username;

    @TableField(value = "`password`")
    private String password;

    @TableField(value = "enabled")
    private Boolean enabled;
}