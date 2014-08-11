package com.prl.demo;

import com.prl.demo.commons.CertificateUtils;

public class CertificateUtilsDemo {
	private final static String KeyStorePath = "attachment/mykeystore";
	private final static String KeyStorePassword = "123456";
	private final static String KeystoreAlias = "forhanwan";
	private final static String CertFile = "attachment/forhanwan.cer";
	public final static String SrcString = "helloworld";

	public static void main(String[] args) throws Exception {
//		signDemo();
		cipherDemo();
	}

	public static void signDemo() throws Exception {
		//简单的
		String sign = CertificateUtils.signToBase64(SrcString.getBytes(), KeyStorePath, KeystoreAlias, KeyStorePassword);
		boolean result = CertificateUtils.verifySign(SrcString.getBytes(), sign, CertFile);
		System.out.println(result);

		//复杂点的
		byte[] encodedData = CertificateUtils.encryptByPrivateKey(SrcString.getBytes(), KeyStorePath, KeystoreAlias, KeyStorePassword);
		byte[] decodedData = CertificateUtils.decryptByPublicKey(encodedData, CertFile);

		// 产生签名
		String sign1 = CertificateUtils.signToBase64(encodedData, KeyStorePath, KeystoreAlias, KeyStorePassword);
		System.out.println("签名:\r\n" + sign1);

		// 验证签名
		boolean status = CertificateUtils.verifySign(encodedData, sign1, CertFile);
		System.out.println(status);
	}

	public static void cipherDemo() throws Exception {
		byte[] encryptedData = CertificateUtils.encryptByPrivateKey(SrcString.getBytes(), KeyStorePath, KeystoreAlias, KeyStorePassword);
		byte[] result = CertificateUtils.decryptByPublicKey(encryptedData, CertFile);
		System.out.println(new String(result));
	}
	
	

}
