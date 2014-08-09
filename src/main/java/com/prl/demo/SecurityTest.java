package com.prl.demo;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

public class SecurityTest {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES");
		Key securityKey = KeyGenerator.getInstance("AES").generateKey();
		cipher.init(Cipher.ENCRYPT_MODE, securityKey);
		byte[] result = cipher.doFinal("helloworld".getBytes());
		System.out.println(new String(result));
		
		cipher.init(Cipher.DECRYPT_MODE, securityKey);
		byte[] src = cipher.doFinal(result);
		System.out.println(new String(src));
	}
}
