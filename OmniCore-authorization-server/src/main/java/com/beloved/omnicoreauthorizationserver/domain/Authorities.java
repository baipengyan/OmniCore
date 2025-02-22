package com.beloved.omnicoreauthorizationserver.domain;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

/**
 * @author baipengyan
 */
@Data
@TableName(value = "authorities")
public class Authorities {
    @TableField(value = "username")
    private String username;

    @TableField(value = "authority")
    private String authority;
}