package io.security.authentication.users.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.authentication.domain.dto.AccountDTO;
import io.security.authentication.domain.entity.Account;
import io.security.authentication.users.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;

@Slf4j
@Controller
@RequiredArgsConstructor
public class UserController {
    private final ObjectMapper mapper;
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @PostMapping("/signup")
    public String signup(AccountDTO accountDTO) {
        Account account = mapper.convertValue(accountDTO, Account.class);
        account.setPassword(passwordEncoder.encode(accountDTO.getPassword()));
        userService.createUser(account);

        return "redirect:/";
    }
}
