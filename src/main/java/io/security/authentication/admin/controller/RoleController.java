package io.security.authentication.admin.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.authentication.admin.domain.dto.RoleDto;
import io.security.authentication.admin.domain.entity.Role;
import io.security.authentication.admin.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.List;

@Controller
@RequiredArgsConstructor
public class RoleController {
    private final RoleService roleService;
    private final ObjectMapper mapper;

    @GetMapping("/admin/roles")
    public String getRoles(Model model) {
        List<Role> roles = roleService.getRoles();
        model.addAttribute("roles", roles);
        return "admin/roles";
    }

    @GetMapping("/admin/roles/register")
    public String rolesRegister(Model model) {
        RoleDto role = new RoleDto();
        model.addAttribute("roles", role);
        return "admin/rolesdetails";
    }

    @PostMapping("/admin/roles")
    public String createRole(RoleDto roleDto) {
        Role role = mapper.convertValue(roleDto, Role.class);
        roleService.createRole(role);

        return "redirect:/admin/roles";
    }

    @GetMapping("/admin/roles/{id}")
    public String getRole(@PathVariable Long id, Model model) {
        Role role = roleService.getRole(id);
        RoleDto roleDto = mapper.convertValue(role, RoleDto.class);
        model.addAttribute("roles", roleDto);
        return "admin/rolesdetails";
    }

    @GetMapping("/admin/roles/delete/{id}")
    public String removeRoles(@PathVariable Long id) {
        roleService.deleteRole(id);

        return "/admin/roles";
    }
}
