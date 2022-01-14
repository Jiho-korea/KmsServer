package com.impconsulting.KmsServer;

import java.security.PublicKey;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.Base64Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;

import com.impconsulting.KmsServer.service.KeyGenerator;
import com.impconsulting.KmsServer.util.Pem;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import reactor.netty.http.client.HttpClient;

@SpringBootTest(
		properties = {
				"clientId=forex",
				"charsetName=UTF-8"
				}
		)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KmsServerApplicationTests {

	@Autowired
	Pem pem;
	
	@Autowired
	KeyGenerator keyGenerator;
	
	@Value("${clientId}")
	private String clientId;
	
	@Value("${charsetName}")
	private String charsetName;
	
	@Test
	@Order(1)
	public void apiTest() throws Exception {
		
		String client_secret = "";
		byte[] bytePublicKey = null;
		String strClientSecret = "";
		
		//self signed certificate 자기 서명 인증서 무시를 위한처리
		//모든 인증서를 신뢰할 수 있도록 처리
		SslContext ssl = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build();
		HttpClient httpClient = HttpClient.create().secure(builder -> builder.sslContext(ssl));
		ClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);
		
		// 1.kms getPublicKey
		bytePublicKey = WebTestClient.bindToServer(connector).responseTimeout(java.time.Duration.ofMillis(10000))
					.build()
					.get()
					.uri("https://13.124.44.108:9011/kms/getPublicKey?clientId=" + clientId)
					.exchange().expectBody(String.class).returnResult().getResponseBodyContent();
		
		
		// 2.ksm getClientSecret
		strClientSecret = WebTestClient.bindToServer(connector).responseTimeout(java.time.Duration.ofMillis(10000))
					.build()
					.get()
					.uri("https://13.124.44.108:9011/kms/getClientSecret?clientId=" + clientId)
					.exchange().expectBody(String.class).returnResult().getResponseBody();
		
		// 3.decrypt clientSecret 
		PublicKey key = pem.readPublicKey(bytePublicKey);
		client_secret = keyGenerator.decryptRsa(key, strClientSecret);
		System.out.println("client_secret = [" + client_secret + "]");
		
		// 4.getAccessToken
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("grant_type", "client_credentials");
		params.add("client_name", clientId);
		params.add("client_secret", client_secret);
		
		String accessToken = WebTestClient.bindToServer(connector).responseTimeout(java.time.Duration.ofMillis(10000))
				.build()
				.post()			
				.uri("https://13.124.44.108:9011/auth/oauth/token")
				.contentType(MediaType.MULTIPART_FORM_DATA)
				.header("Authorization", "Basic " + Base64Utils.encodeToString((clientId + ":" + client_secret).getBytes(charsetName)))
				.body(BodyInserters.fromFormData(params))
				.exchange().expectBody(String.class).returnResult().getResponseBody();
		
		System.out.println("getAccessToken = [" + accessToken + "]");
		
		
		// 5.plant read service call
		MultiValueMap<String, String> paramsPlant = new LinkedMultiValueMap<>();
		paramsPlant.add("paging", "true");
		paramsPlant.add("page", "1");
		paramsPlant.add("pageSize", "25");
		paramsPlant.add("sort", "plant");
		paramsPlant.add("sortType", "ASC");
		paramsPlant.add("use_check", "true");
		paramsPlant.add("company", "LBD716");
		
		String plantList = WebTestClient.bindToServer().responseTimeout(java.time.Duration.ofMillis(10000))
				.build()
				.post()
				.uri("http://13.124.44.108:9090/master/plant/read")
				.contentType(MediaType.MULTIPART_FORM_DATA)
				.header("Authorization", "Basic " + Base64Utils.encodeToString((clientId + ":" + client_secret).getBytes(charsetName)))
				.header("scope", "read")
				.body(BodyInserters.fromFormData(paramsPlant))
				.exchange().expectBody(String.class).returnResult().getResponseBody();
		System.out.println("plantList = [" + plantList + "]");
		
		// 6.user read service call
		MultiValueMap<String, String> paramsUser = new LinkedMultiValueMap<>();
		paramsUser.add("paging", "true");
		paramsUser.add("page", "1");
		paramsUser.add("pageSize", "25");
		paramsUser.add("sort", "user_id");
		paramsUser.add("sortType", "ASC");
		paramsUser.add("status", "1");
		paramsUser.add("company", "LBD716");
		
		String userList = WebTestClient.bindToServer().responseTimeout(java.time.Duration.ofMillis(10000))
				.build()
				.post()
				.uri("http://13.124.44.108:9090/master/user/read")
				.contentType(MediaType.MULTIPART_FORM_DATA)
				.header("Authorization", "Basic " + Base64Utils.encodeToString((clientId + ":" + client_secret).getBytes(charsetName)))
				.header("scope", "read")
				.body(BodyInserters.fromFormData(paramsUser))
				.exchange().expectBody(String.class).returnResult().getResponseBody();
		System.out.println("userList = [" + userList + "]");
		
	}
	
}
