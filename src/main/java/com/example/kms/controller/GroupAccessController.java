package com.example.kms.controller;

import com.example.kms.service.GroupAccessService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/group-access")
@RequiredArgsConstructor
public class GroupAccessController {

    private final GroupAccessService groupAccessService;

}
