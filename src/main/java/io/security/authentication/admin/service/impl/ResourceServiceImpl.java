package io.security.authentication.admin.service.impl;

import io.security.authentication.admin.domain.entity.Resource;
import io.security.authentication.admin.repository.ResourceRepository;
import io.security.authentication.admin.service.ResourceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class ResourceServiceImpl implements ResourceService {
    private final ResourceRepository resourceRepository;

    @Transactional
    public Resource getResource(long id) {
        return resourceRepository.findById(id).orElse(new Resource());
    }

    @Transactional
    public List<Resource> getResources() {
        return resourceRepository.findAll(Sort.by(Sort.Order.asc("orderNum")));
    }

    @Transactional
    public void createResource(Resource resource) {
        resourceRepository.save(resource);
    }

    @Transactional
    public void deleteResource(long id) {
        resourceRepository.deleteById(id);
    }
}
