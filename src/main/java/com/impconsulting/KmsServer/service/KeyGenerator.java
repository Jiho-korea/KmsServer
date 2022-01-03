/*
========================================================================
파    일    명 : KeyGenerator.java
========================================================================
작    성    자 : 강지호
작    성    일 : 2021.12.30
작  성  내  용 : 키생성, 복호화 서비스 객체 인터페이스
========================================================================
*/
package com.impconsulting.KmsServer.service;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public interface KeyGenerator {

	// 비대칭 키 생성
	public KeyPair generate()
			throws NoSuchAlgorithmException, InvalidKeySpecException;

	// 암호화
	public String encryptRsa(PrivateKey privateKey, String plainValue) throws Exception;

	// 복호화
	public String decryptRsa(PublicKey publicKey, String encryptedValue) throws Exception;
}
