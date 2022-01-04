/*
========================================================================
파    일    명 : KeyGeneratorImpl.java
========================================================================
작    성    자 : 강지호
작    성    일 : 2021.12.30
작  성  내  용 : KeyGenerator 구현 클래스
========================================================================
*/
package com.impconsulting.KmsServer.service.impl;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import org.springframework.stereotype.Service;
import com.impconsulting.KmsServer.service.KeyGenerator;

@Service("keyGenerator")
public class KeyGeneratorImpl implements KeyGenerator {

	// 비대칭 키 생성
	@Override
	public KeyPair generate()
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

		generator.initialize(2048);

		KeyPair keyPair = generator.genKeyPair();
//		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

//		PublicKey publicKey = keyPair.getPublic();
//		PrivateKey privateKey = keyPair.getPrivate();

//		RSAPublicKeySpec publicSpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
//		String publicKeyModulus = publicSpec.getModulus().toString(16);
//		String publicKeyExponent = publicSpec.getPublicExponent().toString(16);

		return keyPair;
	}

	// 암호화
	@Override
	public String encryptRsa(PrivateKey privateKey, String plainValue) throws Exception {

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		byte[] encryptedBytes = cipher.doFinal(plainValue.getBytes(StandardCharsets.UTF_8));
		String encryptedValue = Base64.getEncoder().encodeToString(encryptedBytes);

		return encryptedValue;
	}

	// 복호화
	@Override
	public String decryptRsa(PublicKey publicKey, String encryptedValue) throws Exception {

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		byte[] encryptedBytes = Base64.getDecoder().decode(encryptedValue);
		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
		String decryptedValue = new String(decryptedBytes, StandardCharsets.UTF_8);

		return decryptedValue;
	}
}
