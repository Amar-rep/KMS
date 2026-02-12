package com.example.kms.service;

import com.example.kms.entity.AppUser;
import com.example.kms.entity.GroupAccess;
import com.example.kms.entity.GroupKey;
import com.example.kms.entity.Hospital;
import com.example.kms.repository.AppUserRepository;
import com.example.kms.repository.GroupAccessRepository;
import com.example.kms.repository.GroupKeyRepository;
import com.example.kms.repository.HospitalRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class GroupAccessService {

    private final GroupAccessRepository groupAccessRepository;
    private final GroupKeyRepository groupKeyRepository;
    private final AppUserRepository appUserRepository;
    private final HospitalRepository hospitalRepository;

    @Transactional
    public void createGroupAccess(GroupKey groupKey, AppUser doctor, Hospital hospital, String encGroupKey) {

        GroupAccess groupAccess = GroupAccess.builder()
                .groupKey(groupKey)
                .doctor(doctor)
                .hospital(hospital)
                .encGroupKey(encGroupKey)
                .expiresAt(OffsetDateTime.now().plusDays(30))
                .status("ACTIVE")
                .build();

        groupAccessRepository.save(groupAccess);
    }

    public List<GroupAccess> getGroupAccesses(String hospitalId, String doctorId) {
        return groupAccessRepository.findByHospital_HospitalIdAndDoctor_UserIdKeccak(hospitalId, doctorId);
    }
}
