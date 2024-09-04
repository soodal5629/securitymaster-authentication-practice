package io.security.authentication.admin.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Getter
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Resource {
    @Id @GeneratedValue
    @Column(name = "resource_id")
    private Long id;
    private String resourceName;
    private String httpMethod;
    private int orderNum;
    private String resourceType;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "role_resources", joinColumns = {@JoinColumn(name = "resource_id")}, inverseJoinColumns = {@JoinColumn(name = "role_id")})
    @ToString.Exclude
    private Set<Role> roleSet = new HashSet<Role>();
}
