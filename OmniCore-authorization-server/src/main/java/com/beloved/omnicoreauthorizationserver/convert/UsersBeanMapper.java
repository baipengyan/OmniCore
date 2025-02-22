package com.beloved.omnicoreauthorizationserver.convert;

import com.beloved.omnicoreauthorizationserver.domain.Users;
import com.beloved.omnicoreauthorizationserver.service.impl.ChickUserDetails;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

/**
 * @author baipengyan
 */
@Mapper
public interface UsersBeanMapper {
    UsersBeanMapper INSTANCE = Mappers.getMapper(UsersBeanMapper.class);

    /**
     * 用户 转换 登录用户
     *
     * @param users 用户
     * @return {@link ChickUserDetails }
     */
    ChickUserDetails usersToUserDetails(Users users);
}
