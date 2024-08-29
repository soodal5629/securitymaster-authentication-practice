package io.security.authentication.admin.service;

import io.security.authentication.admin.domain.entity.Role;

import java.util.List;

public interface RoleService {
    List<Role> getRoles();

    void createRole(Role role);

    Role getRole(Long id);

    void deleteRole(Long id);
}
