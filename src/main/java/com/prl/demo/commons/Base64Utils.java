package com.prl.demo.commons;

import org.apache.commons.codec.binary.Base64;

public class Base64Utils {

	public static byte[] decode(String base64String) {
		byte[] b = base64String.getBytes();
		return new Base64().decode(b);
	}

	public static String encode(byte[] b) {
		b = new Base64().encode(b);
		return new String(b);
	}

}
