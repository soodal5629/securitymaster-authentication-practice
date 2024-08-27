package io.security.authentication.users.controller;

import io.security.authentication.domain.dto.AccountDTO;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class RestApiController {

    @GetMapping("/user")
    public AccountDTO restUser(@AuthenticationPrincipal AccountDTO user) {
        return user;
    }

    @GetMapping("/manager")
    public AccountDTO restManager(@AuthenticationPrincipal AccountDTO user) {
        return user;
    }

    @GetMapping("/admin")
    public AccountDTO restAdmin(@AuthenticationPrincipal AccountDTO user) {
        return user;
    }
}
