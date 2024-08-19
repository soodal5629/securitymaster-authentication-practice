package io.security.authentication.domain;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AccountDTO {
    private String id;
    private String username;
    private String password;
    private Integer age;
    private String roles;
}
