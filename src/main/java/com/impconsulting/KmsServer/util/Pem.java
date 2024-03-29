package com.impconsulting.KmsServer.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.stereotype.Component;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Component
public class Pem {	
	private PemObject pemObject;

	public Pem(Key key, String description) {
		this.pemObject = new PemObject(description, key.getEncoded());
	}

	public void write(String keyPath) throws FileNotFoundException, IOException {
		File file = new File(keyPath);
		PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(file)));
		try {
			pemWriter.writeObject(this.pemObject);
		} finally {
			pemWriter.close();
		}
	}
	
	public void writePemFile(Key key, String description, String filename)
			throws FileNotFoundException, IOException {
		Pem pemFile = new Pem(key, description);
		pemFile.write(filename);
		//System.out.println(String.format("%s를 %s 파일로 내보냈습니다.", description, filename));
	}
	
	public PublicKey readPublicKey(String keyPath) throws Exception {
	    KeyFactory factory = KeyFactory.getInstance("RSA");

	    try (FileReader keyReader = new FileReader(new File(keyPath));
	      PemReader pemReader = new PemReader(keyReader)) {

	        PemObject pemObject = pemReader.readPemObject();
	        byte[] content = pemObject.getContent();
	        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
	        return factory.generatePublic(pubKeySpec);
	    }
	}
	
	public PublicKey readPublicKey(byte[] keyByte) throws Exception {
		KeyFactory factory = KeyFactory.getInstance("RSA");
		
		try (StringReader keyReader = new StringReader(new String(keyByte));
			      PemReader pemReader = new PemReader(keyReader)) {

			        PemObject pemObject = pemReader.readPemObject();
			        byte[] content = pemObject.getContent();
			        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
			        return factory.generatePublic(pubKeySpec);
			    }
		
	}
}
