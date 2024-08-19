package io.security.authentication.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.authentication.domain.dto.AccountContext;
import io.security.authentication.domain.dto.AccountDTO;
import io.security.authentication.domain.entity.Account;
import io.security.authentication.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service("userDetailsService")
@RequiredArgsConstructor
public class FormUserDetailsService implements UserDetailsService {
    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username);
        if(account == null) {
            throw new UsernameNotFoundException("No user found with username " + username);
        }

        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(account.getRoles()));
        AccountDTO accountDTO = objectMapper.convertValue(account, AccountDTO.class);

        return new AccountContext(accountDTO, authorities);
    }
}
