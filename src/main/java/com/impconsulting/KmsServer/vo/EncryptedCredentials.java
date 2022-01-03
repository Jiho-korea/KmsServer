package com.impconsulting.KmsServer.vo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class EncryptedCredentials {
	private String clientId;
    private String encryptedClientSecret;
}
