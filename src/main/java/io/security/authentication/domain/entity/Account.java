package io.security.authentication.domain.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Builder;
import lombok.Data;

@Data
@Entity
public class Account {
    @Id @GeneratedValue
    private Long id;
    private String username;
    private String password;
    private Integer age;
    private String roles;
}
