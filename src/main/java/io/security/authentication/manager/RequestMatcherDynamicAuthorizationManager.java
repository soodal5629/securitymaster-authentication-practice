package io.security.authentication.manager;

import io.security.authentication.admin.repository.ResourceRepository;
import io.security.authentication.mapper.PersistentUrlRoleMapper;
import io.security.authentication.service.DynamicAuthorizationService;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
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
public class RequestMatcherDynamicAuthorizationManager implements AuthorizationManager<HttpServletRequest> {
    List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;

    private static final AuthorizationDecision ACCESS = new AuthorizationDecision(true);
    private final HandlerMappingIntrospector handlerMappingIntrospector;
    private final ResourceRepository resourceRepository;
    private final RoleHierarchy roleHierarchy;

    @PostConstruct
    public void mapping() {
        DynamicAuthorizationService dynamicAuthorizationService = new DynamicAuthorizationService(
                new PersistentUrlRoleMapper(resourceRepository));
        mappings = dynamicAuthorizationService.getUrlRoleMappings()
                .entrySet().stream()
                .map(entry -> new RequestMatcherEntry<>(
                        new MvcRequestMatcher(handlerMappingIntrospector, entry.getKey()),
                                customAuthorizationManager(entry.getValue())))
                .collect(Collectors.toList());
    }
    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest request) {
        for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) {
            RequestMatcher matcher = mapping.getRequestMatcher();
            RequestMatcher.MatchResult matchResult = matcher.matcher(request);
            if(matchResult.isMatch()) {
                AuthorizationManager<RequestAuthorizationContext> manager = mapping.getEntry();
                return manager.check(authentication, new RequestAuthorizationContext(request, matchResult.getVariables()));
            }
        }
        return ACCESS;
    }

    @Override
    public void verify(Supplier<Authentication> authentication, HttpServletRequest object) {
        AuthorizationManager.super.verify(authentication, object);
    }

    private AuthorizationManager<RequestAuthorizationContext> customAuthorizationManager(String role) {
        if(role.startsWith("ROLE")) {
            AuthorityAuthorizationManager<RequestAuthorizationContext> authorityAuthorizationManager = AuthorityAuthorizationManager.hasAuthority(role);
            authorityAuthorizationManager.setRoleHierarchy(roleHierarchy);
            return authorityAuthorizationManager;
            //return AuthorityAuthorizationManager.hasAuthority(role);
        } else {
            DefaultHttpSecurityExpressionHandler handler = new DefaultHttpSecurityExpressionHandler();
            handler.setRoleHierarchy(roleHierarchy);
            WebExpressionAuthorizationManager webExpressionAuthorizationManager = new WebExpressionAuthorizationManager(role);
            webExpressionAuthorizationManager.setExpressionHandler(handler);
            return webExpressionAuthorizationManager;
            //return new WebExpressionAuthorizationManager(role);
        }
    }
}
