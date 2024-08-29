package io.security.authentication.admin.domain.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Data
public class Role {
    @Id @GeneratedValue
    private Long id;
    private String roleName;
    private String roleDesc;
    private String isExpression;

}
