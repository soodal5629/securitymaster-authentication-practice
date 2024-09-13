package io.security.authentication.config;

import io.security.authentication.admin.service.RoleHierarchyService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AuthConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // 커스텀 계층 권한 적용
    @Bean
    public RoleHierarchy roleHierarchy(RoleHierarchyService roleHierarchyService) {
        String allHierarchy = roleHierarchyService.findAllHierarchy();
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        // setHierarchy deprecated되서 이걸로 했는데 얘 계층 권한 안됨.. 이상하게 오류 남
        //roleHierarchy.fromHierarchy(allHierarchy);
        roleHierarchy.setHierarchy(allHierarchy);
        return roleHierarchy;
    }
}
