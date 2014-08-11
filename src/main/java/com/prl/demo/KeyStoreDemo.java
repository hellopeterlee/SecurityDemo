package com.prl.demo;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

public class KeyStoreDemo {

	private final static String KeyStorePath = "attachment/mykeystore";
	private final static String KeyStorePassword = "123456";
	private final static String KeystoreAlias = "forhanwan";
	private final static String CertFile = "attachment/forhanwan.cer";
	public  final static String SrcString = "helloworld";

	public static final String KEY_STORE_TYPE = "JKS";
	public static final String X509 = "X.509";

	public static void main(String[] args) throws Exception {
		demo();
		jiamijiemiDemo();
	}

	public static void demo() throws Exception {
		byte[] signResult = sign(SrcString.getBytes());
		veriSign(SrcString.getBytes(), signResult);
	}

	private static Certificate getCertificate(String certificatePath) throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance(X509);
		FileInputStream in = new FileInputStream(certificatePath);
		Certificate certificate = certificateFactory.generateCertificate(in);
		in.close();
		return certificate;
	}

	public static byte[] sign(byte[] sigText) throws Exception {
		KeyStore keystore = KeyStore.getInstance(KEY_STORE_TYPE);
		FileInputStream ksfis = new FileInputStream(KeyStorePath);
		BufferedInputStream ksbufin = new BufferedInputStream(ksfis);
		char[] kpass = KeyStorePassword.toCharArray();
		keystore.load(ksbufin, kpass);
		PrivateKey priv = (PrivateKey) keystore.getKey(KeystoreAlias, kpass);

		X509Certificate x509Certificate = (X509Certificate)getCertificate(CertFile);
		Signature rsa = Signature.getInstance(x509Certificate.getSigAlgName());
		rsa.initSign(priv);
		rsa.update(sigText);
		byte[] sig = rsa.sign();
		System.out.println("sig is done");
		return sig;
	}

	public static boolean veriSign(byte[] src, byte[] sign) throws Exception {
		X509Certificate x509Certificate = (X509Certificate)getCertificate(CertFile);
		Signature rsa = Signature.getInstance(x509Certificate.getSigAlgName());
		rsa.initVerify(x509Certificate.getPublicKey());
		rsa.update(src);
		boolean verifies = rsa.verify(sign);
		System.out.println("verified " + verifies);
		if (verifies) {
			System.out.println("Verify is done!");
		} else {
			System.out.println("verify is not successful");
		}
		return verifies;
	}

	public static void jiamijiemiDemo() throws Exception {
		// 私钥从keystore获取
		KeyStore ks = KeyStore.getInstance(KEY_STORE_TYPE);
		FileInputStream ksfis = new FileInputStream(KeyStorePath);
		BufferedInputStream ksbufin = new BufferedInputStream(ksfis);
		char[] kpass = KeyStorePassword.toCharArray();
		ks.load(ksbufin, kpass);
		PrivateKey privateKey = (PrivateKey) ks.getKey(KeystoreAlias, kpass);
		
		// 公钥从证书获取,证书从keystore导出
		CertificateFactory certificatefactory = CertificateFactory.getInstance(X509);
		FileInputStream fin = new FileInputStream(CertFile);
		X509Certificate certificate = (X509Certificate) certificatefactory.generateCertificate(fin);
		PublicKey publicKey = certificate.getPublicKey();
		
		Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
		// 加密
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] result = cipher.doFinal(SrcString.getBytes());
		System.out.println(new String(result));
		
		// 解密
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] src = cipher.doFinal(result);
		System.out.println(new String(src));
	}
}
