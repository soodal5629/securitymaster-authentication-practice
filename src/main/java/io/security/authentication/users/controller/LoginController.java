package io.security.authentication.users.controller;

import io.security.authentication.domain.dto.AccountDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String login(@RequestParam(required = false) String error, @RequestParam(required = false) String exception, Model model) {
        model.addAttribute("error", error);
         model.addAttribute("exception", exception);

        return "login/login";
    }
    @GetMapping("/signup")
    public String signup() {
        return "login/signup";
    }

    /**
     * 커스텀하게 GET 방식으로 로그아웃 처리
     * 사실 Logout 필터의 post 방식으로 처리하는 것이 더 안전함
     */
    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();
        if(authentication != null) {
            // 세션 무효화 & 인증 객체 삭제, clear security context
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        return "redirect:/login";
    }

    @GetMapping("/denied")
    public String denied(@RequestParam(required = false) String exception, @AuthenticationPrincipal AccountDTO login, Model model) {
        model.addAttribute("username", login.getUsername());
        model.addAttribute("exception", exception);

        return "login/denied";
    }

    @GetMapping("/api/login")
    public String restLogin(@RequestParam(required = false) String error, @RequestParam(required = false) String exception, Model model) {
        model.addAttribute("error", error);
        model.addAttribute("exception", exception);

        return "rest/login";
    }
}
