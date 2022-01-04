package com.impconsulting.KmsServer.controller;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
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
public class KmsController {

	private static final Log LOG = LogFactory.getLog(KmsController.class);

	@Autowired
	KeyGenerator keyGenerator;
	
	@Autowired
	Pem pem;
	
	@Autowired
	private VaultTemplate vaultTemplate;

	@GetMapping("/getPublicKey")
	public @ResponseBody ResponseEntity<Resource> getPublicKey(@RequestParam("clientId") String pClientId, Model model) throws Exception {
		// 암호화된 secret 삭제
		vaultTemplate.delete("core/"+ pClientId + "/encrypted");
		
		// 시크릿엔진 kv 조회
		VaultResponseSupport<Credentials> result = vaultTemplate.read("core/"+ pClientId, Credentials.class);
		if(result == null) {
			return new ResponseEntity<Resource>(HttpStatus.NOT_FOUND);   
		}
		String clientId = result.getData().getClientId();
		String clientSecret = result.getData().getClientSecret();
		
		// 키 생성
		KeyPair keyPair = keyGenerator.generate();
		//LOG.info("plain clientId: " + clientId);
		LOG.info("plain clientSecret: " + clientSecret);
		
		String encryptedClientSecret = keyGenerator.encryptRsa(keyPair.getPrivate(), clientSecret);
		
		//LOG.info("private Key: " + keyPair.getPrivate() + "\n");
		LOG.info("encrypted ClientSecret: " + encryptedClientSecret);
		
		// private Key => pem 파일 저장 (테스트용)
		//pem.writePemFile(keyPair.getPublic(), "RSA PRIVATE KEY", "private.pem");
		
		// 암호화된 clientSecret을 하위(/encrypted) 시크릿 엔진에 저장
		EncryptedCredentials encryptedCredentials = new EncryptedCredentials(clientId, encryptedClientSecret);
		vaultTemplate.write("core/"+ pClientId + "/encrypted", encryptedCredentials); // 우선 고정 secret engine에 비밀번호 저장
		
		// public 키를 이용한 복호화 (테스트용)
		String decryptedClientSecret = keyGenerator.decryptRsa(keyPair.getPublic(), encryptedClientSecret);
		//LOG.info("public Key: " + keyPair.getPublic() + "\n");
		LOG.info("decrypted ClientSecret: " + decryptedClientSecret);
		
		// public Key => pem 파일 저장
		pem.writePemFile(keyPair.getPublic(), "RSA PUBLIC KEY", "public.pem");
		
		// 테스트용 clientId, clientSecret 리턴
//		Map<String, Object> data = new HashMap<String, Object>();
//		data.put("clientId", clientId);
//		data.put("clientSecret", clientSecret);
		
		// public key 저장 위치
		String path = "src/main/resources/key/public.pem";
		
		// pem 파일 다운로드 
		try {
			Path filePath = Paths.get(path);
			Resource resource = new InputStreamResource(Files.newInputStream(filePath)); // 파일 resource 얻기
			
			File file = new File(path);
			
			HttpHeaders headers = new HttpHeaders();
			headers.setContentDisposition(ContentDisposition.builder("attachment").filename(file.getName()).build());  // 다운로드 되거나 로컬에 저장되는 용도로 쓰이는지를 알려주는 헤더
			
			return new ResponseEntity<Resource>(resource, headers, HttpStatus.OK);
		} catch(Exception e) {
			return new ResponseEntity<Resource>(HttpStatus.CONFLICT);
		}
	}
	
	@GetMapping("/getClientSecret")
	public @ResponseBody ResponseEntity<String> getClientSecret(@RequestParam("clientId") String pClientId, Model model) throws Exception {
		// 시크릿엔진 kv 조회
		VaultResponseSupport<EncryptedCredentials> result = vaultTemplate.read("core/"+ pClientId + "/encrypted", EncryptedCredentials.class);
		if(result == null) {
			return new ResponseEntity<String>(HttpStatus.NOT_FOUND);   
		}
		String clientId = result.getData().getClientId();
		String encryptedClientSecret = result.getData().getEncryptedClientSecret();
		
		LOG.info("encrypted ClientSecret: " + encryptedClientSecret);
		
		// public.pem 파일을 통한 복호화 테스트 코드
		// public Key 불러오기
		PublicKey key = pem.readPublicKey("public.pem");
		// public 키를 이용한 복호화 (테스트용)
		String decryptedClientSecret = keyGenerator.decryptRsa(key, encryptedClientSecret);
		//LOG.info("public Key: " + keyPair.getPublic() + "\n");
		LOG.info("decrypted ClientSecret: " + decryptedClientSecret);
				
		// 암호화된 secret 삭제
		vaultTemplate.delete("core/"+ pClientId + "/encrypted");
		
		// 테스트용 clientId, clientSecret 리턴
//		Map<String, Object> data = new HashMap<String, Object>();
//		data.put("clientId", clientId);
//		data.put("clientSecret", clientSecret);
		
		return new ResponseEntity<String>(encryptedClientSecret, HttpStatus.OK);

	}
}
