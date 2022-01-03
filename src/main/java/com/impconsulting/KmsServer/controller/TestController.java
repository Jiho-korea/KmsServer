package com.impconsulting.KmsServer.controller;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponseSupport;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.impconsulting.KmsServer.service.KeyGenerator;
import com.impconsulting.KmsServer.util.Pem;
import com.impconsulting.KmsServer.vo.Credentials;
import com.impconsulting.KmsServer.vo.EncryptedCredentials;

@RestController
public class TestController {

	private static final Log LOG = LogFactory.getLog(TestController.class);

	@Autowired
	KeyGenerator keyGenerator;
	
	@Autowired
	Pem pem;
	
	@Autowired
	private VaultTemplate vaultTemplate;

	@GetMapping("/getPublicKey")
	public @ResponseBody ResponseEntity<Map<String, Object>> getPublicKey(@RequestParam("clientId") String pClientId, Model model) throws Exception {
		VaultResponseSupport<Credentials> result = vaultTemplate.read("test/"+ pClientId, Credentials.class);
		if(result == null) {
			return new ResponseEntity<Map<String, Object>>(HttpStatus.NOT_FOUND);   
		}
		String clientId = result.getData().getClientId();
		String clientSecret = result.getData().getClientSecret();
		
		KeyPair keyPair = keyGenerator.generate();
		//LOG.info("plain clientId: " + clientId);
		LOG.info("plain clientSecret: " + clientSecret);
		
		String encryptedClientSecret = keyGenerator.encryptRsa(keyPair.getPrivate(), clientSecret);
		
		LOG.info("private Key: " + keyPair.getPrivate() + "\n");
		LOG.info("encrypted ClientSecret: " + encryptedClientSecret);
		
		// 암호화된 clientSecret을 하위 시크릿 엔진에 저장
		EncryptedCredentials encryptedCredentials = new EncryptedCredentials(clientId, encryptedClientSecret);
		vaultTemplate.write("test/test/encrypted", encryptedCredentials); // 우선 고정 secret engine에 비밀번호 저장
		
		String decryptedClientSecret = keyGenerator.decryptRsa(keyPair.getPublic(), encryptedClientSecret);
		 
		LOG.info("public Key: " + keyPair.getPublic() + "\n");
		LOG.info("decrypted ClientSecret: " + decryptedClientSecret);
		
		pem.writePemFile(keyPair.getPublic(), "RSA PUBLIC KEY", "public.pem");
		
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("clientId", clientId);
		data.put("clientSecret", clientSecret);
		
		return new ResponseEntity<Map<String, Object>>(data, HttpStatus.OK);   
	}
	
	@GetMapping("/read")
	public @ResponseBody ResponseEntity<Map<String, Object>> read(Model model) throws Exception {
		VaultResponseSupport<Credentials> result = vaultTemplate.read("test/test/encrypted/123456", Credentials.class);
		String clientId = result.getData().getClientId();
		String clientSecret = result.getData().getClientSecret();
		
		Map<String, Object> data = new HashMap<String, Object>();
		data.put("clientId", clientId);
		data.put("clientSecret", clientSecret);
		
		return new ResponseEntity<Map<String, Object>>(data, HttpStatus.OK);   
	}
	
	@GetMapping("/write")
	public @ResponseBody ResponseEntity<String> write(Model model) throws Exception {
		Credentials credentials = new Credentials("admin", "1111");
		vaultTemplate.write("test/test/encrypted/123456", credentials);
		
		return new ResponseEntity<String>("write success", HttpStatus.OK);
	}
	
	@GetMapping("/delete")
	public @ResponseBody ResponseEntity<String> delete(Model model) throws Exception {
		vaultTemplate.delete("test/test/encrypted/123456");
		
		return new ResponseEntity<String>("delete success", HttpStatus.OK);
	}
	
	@GetMapping("/deleteUpper")
	public @ResponseBody ResponseEntity<String> deleteUpper(Model model) throws Exception {
		vaultTemplate.delete("test/test/encrypted/*");
		return new ResponseEntity<String>("delete success", HttpStatus.OK);
	}
}
