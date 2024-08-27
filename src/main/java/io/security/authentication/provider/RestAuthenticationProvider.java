package io.security.authentication.provider;

import io.security.authentication.details.FormAuthenticationDetails;
import io.security.authentication.domain.dto.AccountContext;
import io.security.authentication.exception.SecretException;
import io.security.authentication.token.RestAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * REST 인증 방식 Provider
 */
@Component("restAuthenticationProvider")
@RequiredArgsConstructor
public class RestAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String loginId = authentication.getName();
        String password = (String) authentication.getCredentials();
        AccountContext user = (AccountContext) userDetailsService.loadUserByUsername(loginId);

        if(!passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException("Invalid Password");
        }

        return new RestAuthenticationToken(user.getAuthorities(), user.getAccountDTO(), null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(RestAuthenticationToken.class);
    }
}
