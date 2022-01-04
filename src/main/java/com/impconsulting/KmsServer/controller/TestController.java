package com.impconsulting.KmsServer.controller;

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
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.impconsulting.KmsServer.vo.Credentials;

@RestController
public class TestController {

	private static final Log LOG = LogFactory.getLog(TestController.class);
	
	@Autowired
	private VaultTemplate vaultTemplate;
	
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
