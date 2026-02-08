package com.example.kms.controller;

import com.example.kms.dto.CreateGroupResponseDTO;
import com.example.kms.dto.RegisterGroupDTO;
import com.example.kms.entity.GroupKey;
import com.example.kms.service.GroupService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/groups")
@RequiredArgsConstructor
public class GroupController {

    private final GroupService groupService;

    /**
     * POST /api/groups/create
     * Create a new group with generated DEK and Group Key
     * 
     * @param registerGroupDTO Request containing user_keccak and group name
     * @return CreateGroupResponseDTO containing group details and encrypted DEK
     */
    @PostMapping("/create")
    public ResponseEntity<CreateGroupResponseDTO> createGroup(@RequestBody RegisterGroupDTO registerGroupDTO) {
        try {

            // Call service to create group
            GroupKey groupKey = groupService.createGroup(registerGroupDTO);

            // Build response
            CreateGroupResponseDTO response = new CreateGroupResponseDTO(
                    groupKey.getGroupId(),
                    groupKey.getGroupName(),
                    groupKey.getEncDekUser(),
                    groupKey.getUser().getUserIdKeccak());

            log.info("Group created successfully: GroupID={}, Name={}",
                    response.getGroupId(), response.getGroupName());

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            log.error("Group creation failed", e);
            throw e;
        }
    }
}
