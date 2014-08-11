package com.prl.demo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

import org.apache.commons.io.IOUtils;

public class PublicPrivateKey {

	public static final String AlgorithRSA = "RSA";
	public static String SrcString = "helloworld";
	public static byte[] Salt = new byte[] { (byte) 0x8E, 0x12, 0x39, (byte) 0x9C, 0x07, 0x72, 0x6F, 0x5A };

	public static void main(String[] args) throws Exception {
		demo1();
	}

	public static void demo() throws Exception {
		Cipher cipher = Cipher.getInstance(AlgorithRSA);
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AlgorithRSA);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		// 加密
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] result = cipher.doFinal(SrcString.getBytes());
		System.out.println(new String(result));

		// 解密
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] src = cipher.doFinal(result);
		System.out.println(new String(src));
	}

	public static void demo1() throws Exception {
		Cipher cipher = Cipher.getInstance(AlgorithRSA);
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AlgorithRSA);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		// 加密
		ByteArrayInputStream is = new ByteArrayInputStream(SrcString.getBytes());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		CipherInputStream cipherInputStream = new CipherInputStream(is, cipher);
		IOUtils.copy(cipherInputStream, outputStream);
		
		System.out.println("after:" + new String(outputStream.toByteArray()));

		// 解密
		ByteArrayInputStream bis = new ByteArrayInputStream(outputStream.toByteArray());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		cipherInputStream = new CipherInputStream(bis, cipher);
		ByteArrayOutputStream outputStream1 = new ByteArrayOutputStream();
		IOUtils.copy(cipherInputStream, outputStream1);
		System.out.println("before:" + new String(outputStream1.toByteArray()));
	}
}
