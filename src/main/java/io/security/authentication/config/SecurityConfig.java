package io.security.authentication.config;

import io.security.authentication.filters.RestAuthenticationFilter;
import io.security.authentication.handler.FormAccessDeniedHandler;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    // private final UserDetailsService userDetailsService;
    private final AuthenticationProvider authenticationProvider;
    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;
    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    private final AuthenticationProvider restAuthenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                                .requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*").permitAll() // 정적 자원 설정
                .requestMatchers("/", "/signup", "/login*").permitAll()
                .requestMatchers("/user").hasRole("USER")
                .requestMatchers("/manager").hasRole("MANAGER")
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()
                )
            .formLogin(form -> form
                    .loginPage("/login").permitAll()
                    .authenticationDetailsSource(authenticationDetailsSource)
                    .successHandler(successHandler)
                    .failureHandler(failureHandler)

            )
            .authenticationProvider(authenticationProvider)
            .exceptionHandling(e -> e.accessDeniedHandler(new FormAccessDeniedHandler("/denied")))
            //.userDetailsService(userDetailsService)
        ;
        return http.build();
    }

    // rest 인증 보안 (위의 form 인증 방식 securityFilterChain 까지 합해서 다중 보안 처리)
    @Bean
    @Order(1)
    public SecurityFilterChain restSecurityFilterChain(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder managerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        managerBuilder.authenticationProvider(restAuthenticationProvider);
        AuthenticationManager authenticationManager = managerBuilder.build();

        http
                .securityMatcher("/api/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*").permitAll() // 정적 자원 설정
                        .anyRequest().permitAll()
                )
            .csrf(AbstractHttpConfigurer::disable)
            .addFilterBefore(restAuthenticationFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
            .authenticationManager(authenticationManager)
        ;
        return http.build();
    }

    private RestAuthenticationFilter restAuthenticationFilter(AuthenticationManager authenticationManager) {
        RestAuthenticationFilter restAuthenticationFilter = new RestAuthenticationFilter();
        restAuthenticationFilter.setAuthenticationManager(authenticationManager);
        return restAuthenticationFilter;

    }

    //@Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        return new InMemoryUserDetailsManager(user);
    }
}
