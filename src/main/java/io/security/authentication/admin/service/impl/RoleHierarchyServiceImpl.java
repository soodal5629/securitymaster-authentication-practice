package io.security.authentication.admin.service.impl;

import io.security.authentication.admin.domain.entity.RoleHierarchy;
import io.security.authentication.admin.repository.RoleHierarchyRepository;
import io.security.authentication.admin.service.RoleHierarchyService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Iterator;
import java.util.List;

@Service
@RequiredArgsConstructor
public class RoleHierarchyServiceImpl implements RoleHierarchyService {
    private final RoleHierarchyRepository roleHierarchyRepository;

    @Override
    public String findAllHierarchy() {
        List<RoleHierarchy> rolesHierarchy = roleHierarchyRepository.findAll();
        Iterator<RoleHierarchy> iter = rolesHierarchy.iterator();
        StringBuilder hierarchyRole = new StringBuilder();
        while (iter.hasNext()) {
            RoleHierarchy roleHierarchy = iter.next();
            if(roleHierarchy.getParent() != null) {
                hierarchyRole.append(roleHierarchy.getParent().getRoleName());
                hierarchyRole.append(" > ");
                hierarchyRole.append(roleHierarchy.getRoleName());
                hierarchyRole.append("\n");
            }
        }
        return hierarchyRole.toString();
    }
}
