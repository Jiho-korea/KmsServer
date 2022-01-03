package com.impconsulting.KmsServer;


import java.net.URI;
import java.net.URISyntaxException;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.config.AbstractVaultConfiguration;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class VaultConfig extends AbstractVaultConfiguration {

	@Value("${spring.cloud.vault.uri}")
	private String VAULT_ADDR_URI;
	
	@Value("${spring.cloud.vault.host}")
	private String VAULT_ADDR_HOST;
	
	@Value("${spring.cloud.vault.port}")
	private int VAULT_ADDR_PORT;
	
	@Value("${spring.cloud.vault.token}")
	private String VAULT_TOKEN;
	
    @Override
    public ClientAuthentication clientAuthentication() {
        return new TokenAuthentication(VAULT_TOKEN);
    }

    @Override
    public VaultEndpoint vaultEndpoint() {
        //return VaultEndpoint.create(VAULT_ADDR_HOST, VAULT_ADDR_PORT);
        try {
			return VaultEndpoint.from(new URI(VAULT_ADDR_URI));
		} catch (URISyntaxException e) {
			return null;
		}
    }
    
    @Bean
    public VaultTemplate vaultTemplate() {
		// Vault 서버에 접근 하기 위한 VaultTemplate 객체
		return new VaultTemplate(vaultEndpoint(), clientAuthentication());
    }
}
