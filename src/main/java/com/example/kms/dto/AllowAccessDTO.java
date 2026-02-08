package com.example.kms.dto;

import lombok.Data;

@Data
public class AllowAccessDTO {

    private String sender_keccak;
    private String receiver_keccak;
    private String groupId;
    private String nonce;
    private String signature;

}
