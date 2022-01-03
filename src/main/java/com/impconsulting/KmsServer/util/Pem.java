package com.impconsulting.KmsServer.util;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.Key;

import org.bouncycastle.util.io.pem.PemObject;
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

	public void write(String filename) throws FileNotFoundException, IOException {
		File file = new File("src/main/resources/key/" + filename);
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
}
