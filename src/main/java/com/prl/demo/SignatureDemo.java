package com.prl.demo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SignatureDemo {
	public static final String AlgorithMD5withRSA = "MD5withRSA";
	public static final String AlgorithRSA = "RSA";
	public static String SrcString = "helloworld";
	
	public static void main(String[] args) throws Exception {
		demo();
	}
	
	public static void demo() throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AlgorithRSA);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		//签名
		Signature signature = Signature.getInstance(AlgorithMD5withRSA);
		signature.initSign(privateKey);
		signature.update(SrcString.getBytes());
		byte[] signResult = signature.sign();
		
		signature.initVerify(publicKey);
		signature.update(SrcString.getBytes());
		boolean verifyResult = signature.verify(signResult);
		System.out.println(verifyResult);
	}
}
