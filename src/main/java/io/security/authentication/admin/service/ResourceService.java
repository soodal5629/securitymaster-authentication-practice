package io.security.authentication.admin.service;

import io.security.authentication.admin.domain.entity.Resource;

import java.util.List;

public interface ResourceService {
    List<Resource> getResources();
    Resource getResource(long id);
    void createResource(Resource Resources);
    void deleteResource(long id);
}
