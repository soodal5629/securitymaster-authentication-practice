package io.security.authentication.admin.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.authentication.admin.domain.dto.ResourceDto;
import io.security.authentication.admin.domain.entity.Resource;
import io.security.authentication.admin.domain.entity.Role;
import io.security.authentication.admin.repository.RoleRepository;
import io.security.authentication.admin.service.ResourceService;
import io.security.authentication.admin.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Controller
@RequestMapping("/admin/resources")
@RequiredArgsConstructor
public class ResourceController {
    private final ResourceService resourceService;
    private final RoleRepository roleRepository;
    private final RoleService roleService;
    private final ObjectMapper objectMapper;

    @GetMapping
    public String getResources(Model model) {
        List<Resource> resources = resourceService.getResources();
        model.addAttribute("resources", resources);
        return "admin/resources";
    }

    @PostMapping
    public String createResources(ResourceDto resourcesDto) {
        Role role = roleRepository.findByRoleName(resourcesDto.getRoleName());
        Set<Role> roles = new HashSet<>();
        roles.add(role);
        Resource resources = objectMapper.convertValue(resourcesDto, Resource.class);
        resources.setRoleSet(roles);
        resourceService.createResource(resources);

        return "redirect:/admin/resources";
    }

    @GetMapping("/register")
    public String resourcesRegister(Model model) {
        List<Role> roleList = roleService.getRoles();
        model.addAttribute("roleList", roleList);
        List<String> myRoles = new ArrayList<>();
        model.addAttribute("myRoles", myRoles);
        ResourceDto resources = new ResourceDto();
        Set<Role> roleSet = new HashSet<>();
        roleSet.add(new Role());
        resources.setRoleSet(roleSet);
        model.addAttribute("resources", resources);
        return "admin/resourcesdetails";
    }

    @GetMapping(value="/{id}")
    public String resourceDetails(@PathVariable String id, Model model) {

        List<Role> roleList = roleService.getRoles();
        model.addAttribute("roleList", roleList);
        Resource resources = resourceService.getResource(Long.parseLong(id));
        List<String> myRoles = resources.getRoleSet().stream().map(role -> role.getRoleName()).toList();
        model.addAttribute("myRoles", myRoles);
        ResourceDto resourcesDto = objectMapper.convertValue(resources, ResourceDto.class);
        model.addAttribute("resources", resourcesDto);

        return "admin/resourcesdetails";
    }

    @GetMapping(value="/delete/{id}")
    public String removeResources(@PathVariable String id) throws Exception {

        resourceService.deleteResource(Long.parseLong(id));

        return "redirect:/admin/resources";
    }

}
