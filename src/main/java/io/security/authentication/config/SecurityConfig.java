package io.security.authentication.config;

import io.security.authentication.dsl.RestApiDsl;
import io.security.authentication.entrypoint.RestAuthenticationEntryPoint;
import io.security.authentication.filters.CustomAuthorizationFilter;
import io.security.authentication.filters.RestAuthenticationFilter;
import io.security.authentication.handler.FormAccessDeniedHandler;
import io.security.authentication.handler.FormAuthenticationFailureHandler;
import io.security.authentication.handler.FormAuthenticationSuccessHandler;
import io.security.authentication.handler.RestAccessDeniedHandler;
import io.security.authentication.provider.FormAuthenticationProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    // private final UserDetailsService userDetailsService;
    private final FormAuthenticationProvider formAuthenticationProvider;
    private final AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> authenticationDetailsSource;
    private final FormAuthenticationSuccessHandler successHandler;
    private final FormAuthenticationFailureHandler failureHandler;

    private final AuthenticationProvider restAuthenticationProvider;
    private final AuthenticationSuccessHandler restSuccessHandler;
    private final AuthenticationFailureHandler restFailureHandler;
    //private final AuthorizationManager<RequestAuthorizationContext> authorizationManager;
    private final AuthorizationManager<HttpServletRequest> authorizationManager;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
//                                .requestMatchers("/css/**", "/images/**", "/js/**", "/favicon.*", "/*/icon-*").permitAll() // 정적 자원 설정
//                .requestMatchers("/", "/signup", "/login*").permitAll()
//                .requestMatchers("/user").hasRole("USER")
//                .requestMatchers("/manager").hasRole("MANAGER")
//                .requestMatchers("/admin").hasRole("ADMIN")
//                .anyRequest().authenticated()
                    // 프로그래밍 방식으로 인가 설정 (1. Map 방식, 2. DB 방식)
                    //.anyRequest().access(authorizationManager)
                // 어떤 요청이 오든 CustomAuthorizationFilter가 받을 수 있도록
                                .anyRequest().permitAll()
                )
            .formLogin(form -> form
                    .loginPage("/login").permitAll()
                    .authenticationDetailsSource(authenticationDetailsSource)
                    .successHandler(successHandler)
                    .failureHandler(failureHandler)

            )
            .authenticationProvider(formAuthenticationProvider)
            .exceptionHandling(e -> e.accessDeniedHandler(new FormAccessDeniedHandler("/denied")))
            //.userDetailsService(userDetailsService)
                .addFilterAfter(customAuthorizationFilter(null), ExceptionTranslationFilter.class)
        ;
        return http.build();
    }

    /**
     * 커스텀 필터 추가
     * - 모든 요청에 대해 시큐리티에서 제공하는 AuthorizationFilter가 아닌, 우리가 만든 custom filter가 바로 받을 수 있음
     * - 시큐리티에서 제공하는 AuthorizationFilter조차 타지 않도록 조치
     */
    @Bean
    public CustomAuthorizationFilter customAuthorizationFilter(HttpSecurity http) {
        return new CustomAuthorizationFilter(authorizationManager);
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
                        .requestMatchers("/api", "/api/login").permitAll()
                        .requestMatchers("/api/user").hasRole("USER")
                        .requestMatchers("/api/manager").hasRole("MANAGER")
                        .requestMatchers("/api/admin").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                //.csrf(AbstractHttpConfigurer::disable)
                // DSL 사용하기 때문에 해당 코드 주석 처리
                //.addFilterBefore(restAuthenticationFilter(http, authenticationManager), UsernamePasswordAuthenticationFilter.class)
                .authenticationManager(authenticationManager)
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                        .accessDeniedHandler(new RestAccessDeniedHandler())
                )
                .with(new RestApiDsl<>(), restDsl -> restDsl
                        .restSuccessHandler(restSuccessHandler)
                        .restFailureHandler(restFailureHandler)
                        .loginPage("/api/login")
                        .loginProcessingUrl("/api/login")
                )
        ;
        return http.build();
    }

    private RestAuthenticationFilter restAuthenticationFilter(HttpSecurity http, AuthenticationManager authenticationManager) {
        RestAuthenticationFilter restAuthenticationFilter = new RestAuthenticationFilter(http);
        restAuthenticationFilter.setAuthenticationManager(authenticationManager);
        restAuthenticationFilter.setAuthenticationSuccessHandler(restSuccessHandler);
        restAuthenticationFilter.setAuthenticationFailureHandler(restFailureHandler);
        return restAuthenticationFilter;

    }

    //@Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        return new InMemoryUserDetailsManager(user);
    }
}
