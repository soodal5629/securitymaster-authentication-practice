package io.security.authentication.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.authentication.admin.domain.entity.Role;
import io.security.authentication.domain.dto.AccountContext;
import io.security.authentication.domain.dto.AccountDTO;
import io.security.authentication.admin.domain.entity.Account;
import io.security.authentication.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service("userDetailsService")
@RequiredArgsConstructor
public class FormUserDetailsService implements UserDetailsService {
    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username);
        if(account == null) {
            throw new UsernameNotFoundException("No user found with username " + username);
        }

        //List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(account.getRoles()));
        // 동적 권한 설정
        List<GrantedAuthority> authorities = account.getUserRoles()
                .stream()
                .map(Role::getRoleName)
                .collect(Collectors.toSet())
                .stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

        AccountDTO accountDTO = objectMapper.convertValue(account, AccountDTO.class);

        return new AccountContext(accountDTO, authorities);
    }
}
