package io.security.authentication.provider;

import io.security.authentication.details.FormAuthenticationDetails;
import io.security.authentication.domain.dto.AccountContext;
import io.security.authentication.exception.SecretException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component("authenticationProvider")
@RequiredArgsConstructor
public class FormAuthenticationProvider implements AuthenticationProvider {
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
        // 클라이언트에서 전달한 인증 관련 정보 외 추가 정보
        String secretKey = ((FormAuthenticationDetails) authentication.getDetails()).getSecretKey();
        if (secretKey == null || !"secret".equals(secretKey)) {
            throw new SecretException("Invalid Secret Key");
        }

        return new UsernamePasswordAuthenticationToken(user.getAccountDTO(), null, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }
}
