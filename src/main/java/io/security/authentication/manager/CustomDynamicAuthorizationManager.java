package io.security.authentication.manager;

import io.security.authentication.admin.repository.ResourceRepository;
import io.security.authentication.mapper.MapBasedUrlRoleMapper;
import io.security.authentication.mapper.PersistentUrlRoleMapper;
import io.security.authentication.service.DynamicAuthorizationService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class CustomDynamicAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {
    private List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;
    // private static final AuthorizationDecision DENY = new AuthorizationDecision(false);
    private static AuthorizationDecision ACCESS = new AuthorizationDecision(true);
    private final HandlerMappingIntrospector introspector;
    private final ResourceRepository resourceRepository;
    DynamicAuthorizationService dynamicAuthorizationService;
    private final RoleHierarchy roleHierarchy;

    @PostConstruct
    public void mapping() {
        //DynamicAuthorizationService dynamicAuthorizationService = new DynamicAuthorizationService(new MapBasedUrlRoleMapper());
         dynamicAuthorizationService = new DynamicAuthorizationService(new PersistentUrlRoleMapper(resourceRepository));
        setMapping();
    }

    private void setMapping() {
        mappings = dynamicAuthorizationService.getUrlRoleMappings()
               .entrySet().stream()
               .map(entry -> new RequestMatcherEntry<>(new MvcRequestMatcher(introspector, entry.getKey()), customAuthorizationManager(entry.getValue())))
               .collect(Collectors.toList());
    }

    private AuthorizationManager<RequestAuthorizationContext> customAuthorizationManager(String role) {
        //if (role != null) {
            if(role.startsWith("ROLE")) {
                //return AuthorityAuthorizationManager.hasAuthority(role);
                AuthorityAuthorizationManager<RequestAuthorizationContext> authorityAuthorizationManager =
                        AuthorityAuthorizationManager.hasAuthority(role);
                // 계층 권한 적용해줘야 함
                authorityAuthorizationManager.setRoleHierarchy(roleHierarchy);
                return authorityAuthorizationManager;
            } else { // 표현식
                //return new WebExpressionAuthorizationManager(role);
                // 계층 권한 적용해줘야 함
                DefaultHttpSecurityExpressionHandler handler = new DefaultHttpSecurityExpressionHandler();
                handler.setRoleHierarchy(roleHierarchy);
                WebExpressionAuthorizationManager authorizationManager = new WebExpressionAuthorizationManager(role);
                authorizationManager.setExpressionHandler(handler);
                return authorizationManager;
            }
        //}
        //return null;
    }

    @Override
    public AuthorizationDecision check(Supplier authentication, RequestAuthorizationContext object) {
        RequestAuthorizationContext request = (RequestAuthorizationContext) object;

        for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) { // 모든 인가 설정을 체크한다
            RequestMatcher matcher = mapping.getRequestMatcher();
            RequestMatcher.MatchResult matchResult = matcher.matcher(request.getRequest()); // RequestMatcher(/user) 와 request Url 이 일치하는지 검사
            if (matchResult.isMatch()) {
                AuthorizationManager<RequestAuthorizationContext> manager = mapping.getEntry();
                return manager.check(authentication, // RequestMatcher(/user) 와 매핑된 AuthorizationManager 객체를 가져와서 권한 검사 시작
                        new RequestAuthorizationContext(request.getRequest(), matchResult.getVariables()));
            }
        }
        // mappings에 맞지 않는 request는 deny 한다.
        // return DENY;
        // 이전 버젼에서는 mappings에 맞지 않는 request는 통과시킴
        return ACCESS;
    }

    @Override
    public void verify(Supplier authentication, RequestAuthorizationContext object) {
        AuthorizationManager.super.verify(authentication, object);
    }

    // synchronized - 여러 사용자가 사용하기 때문에 동시성 문제 해결 및 동기화 처리 할 수 있도록(안정성 ↑)
    public synchronized void reload() {
        mappings.clear();
        setMapping();
    }

}
