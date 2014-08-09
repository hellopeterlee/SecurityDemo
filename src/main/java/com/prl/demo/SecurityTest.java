package com.prl.demo;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

@SuppressWarnings("unused")
public class SecurityTest {
	public static final String AlgorithAES = "AES";
	public static final String AlgorithPBE = "PBEWithMD5AndDES";
	public static String SrcString = "helloworld";
	public static String Password = "yourpassword";
	public static byte[] Salt = new byte[] { (byte) 0x8E, 0x12, 0x39, (byte) 0x9C, 0x07, 0x72, 0x6F, 0x5A };

	public static void main(String[] args) throws Exception {
		test2();
	}

	private static void test1() throws Exception {
		// 加密
		Cipher cipher = Cipher.getInstance(AlgorithAES);
		Key securityKey = KeyGenerator.getInstance(AlgorithAES).generateKey();
		cipher.init(Cipher.ENCRYPT_MODE, securityKey);
		byte[] result = cipher.doFinal(SrcString.getBytes());
		System.out.println(new String(result));

		// 解密
		cipher.init(Cipher.DECRYPT_MODE, securityKey);
		byte[] src = cipher.doFinal(result);
		System.out.println(new String(src));
	}

	public static void test2() throws Exception {
		KeySpec keySpec = new PBEKeySpec(Password.toCharArray());
		SecretKey key = SecretKeyFactory.getInstance(AlgorithPBE).generateSecret(keySpec);
		PBEParameterSpec parameterSpec = new PBEParameterSpec(Salt, 1000);
		Cipher cipher = Cipher.getInstance(AlgorithPBE);

		// 加密
		cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
		byte[] result = cipher.doFinal(SrcString.getBytes());
		System.out.println(new String(result));

		// 解密
		cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
		byte[] src = cipher.doFinal(result);
		System.out.println(new String(src));
	}

}
