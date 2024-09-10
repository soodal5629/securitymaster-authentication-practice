package io.security.authentication.mapper;

import io.security.authentication.admin.domain.entity.Resource;
import io.security.authentication.admin.repository.ResourceRepository;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PersistentUrlRoleMapper implements UrlRoleMapper {
    private final LinkedHashMap<String, String> urlRoleMappings = new LinkedHashMap<>();
    private final ResourceRepository resourceRepository;

    public PersistentUrlRoleMapper(ResourceRepository resourceRepository) {
        this.resourceRepository = resourceRepository;
    }

    @Override
    public Map<String, String> getUrlRoleMappings() {
        urlRoleMappings.clear();
        List<Resource> resources = resourceRepository.findAllResources();
        resources.forEach(re -> {
            re.getRoleSet().forEach(role -> {
                urlRoleMappings.put(re.getResourceName(), role.getRoleName());
            });
        });
        return urlRoleMappings;
    }
}
