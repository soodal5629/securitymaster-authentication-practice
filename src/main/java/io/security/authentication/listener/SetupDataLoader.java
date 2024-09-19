package io.security.authentication.listener;

import io.security.authentication.admin.domain.entity.Role;
import io.security.authentication.admin.repository.RoleRepository;
import io.security.authentication.admin.domain.entity.Account;
import io.security.authentication.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {
    private final FilterChainProxy filterChainProxy;
    private boolean alreadySetup = false;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void onApplicationEvent(ContextRefreshedEvent event) {
        if(alreadySetup) {
            return;
        }
        // 기존 시큐리티가 가지고 있는 AuthorizationFilter 제거
        disableAuthorizationFilter();
        setupData();
        alreadySetup = true;
    }

    private void disableAuthorizationFilter() {
        // SecurityConfig에서 빈으로 등록한 2개의 SecurityFilterChain 들을 forEach로 돌며 또 그 내부의 필터들 중에서 마지막 필터를 제거
        filterChainProxy.getFilterChains()
                .forEach(df -> df.getFilters().remove(df.getFilters().size()-1));
    }

    private void setupData() {
        HashSet<Role> roles = new HashSet<>();
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN", "관리자");
        roles.add(adminRole);
        createUserIfNotFound("admin", "admin@admin.com", "pass", roles);
    }

    private Role createRoleIfNotFound(String roleName, String roleDesc) {
        Role role = roleRepository.findByRoleName(roleName);
        if(role == null) {
            role = Role.builder()
                    .roleName(roleName)
                    .roleDesc(roleDesc)
                    .isExpression("N")
                    .build();
        }
        return roleRepository.save(role);
    }

    private void createUserIfNotFound(final String username, final String email, final String password, Set<Role> roles) {
        Account account = userRepository.findByUsername(username);
        if(account == null) {
            account = Account.builder()
                    .username(username)
                    .password(passwordEncoder.encode(password))
                    .userRoles(roles)
                    .build();
        }
        userRepository.save(account);
    }

}
