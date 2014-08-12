package com.prl.demo.commons;

/*
 keytool -validity 365 -genkey -v -alias www.asdc.com.cn -keyalg RSA -keystore D:\key\asdc.keystore -dname "CN=172.25.67.98,OU=stos,O=asdc,L=Haidian,ST=Beijing,c=cn" -storepass 123456 -keypass 123456
 keytool -export -v -alias www.asdc.com.cn -keystore D:\key\asdc.keystore -storepass 123456 -rfc -file D:\key\asdc.cer 

 * */
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.Cipher;

public class CertificateUtils {
	
	public static final String KEY_STORE = "JKS";
	public static final String X509 = "X.509";
	private static final int CACHE_SIZE = 2048;
	private static final int MAX_ENCRYPT_BLOCK = 117;
	private static final int MAX_DECRYPT_BLOCK = 128;

	private static PrivateKey getPrivateKey(String keyStorePath, String alias, String password) throws Exception {
		KeyStore keyStore = getKeyStore(keyStorePath, password);
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
		return privateKey;
	}

	private static KeyStore getKeyStore(String keyStorePath, String password) throws Exception {
		FileInputStream in = new FileInputStream(keyStorePath);
		KeyStore keyStore = KeyStore.getInstance(KEY_STORE);
		keyStore.load(in, password.toCharArray());
		in.close();
		return keyStore;
	}

	private static PublicKey getPublicKey(String certificatePath) throws Exception {
		Certificate certificate = getCertificate(certificatePath);
		PublicKey publicKey = certificate.getPublicKey();
		return publicKey;
	}

	private static Certificate getCertificate(String certificatePath) throws Exception {
		CertificateFactory certificateFactory = CertificateFactory.getInstance(X509);
		FileInputStream in = new FileInputStream(certificatePath);
		Certificate certificate = certificateFactory.generateCertificate(in);
		in.close();
		return certificate;
	}

	private static Certificate getCertificate(String keyStorePath, String alias, String password) throws Exception {
		KeyStore keyStore = getKeyStore(keyStorePath, password);
		Certificate certificate = keyStore.getCertificate(alias);
		return certificate;
	}

	public static byte[] encryptByPrivateKey(byte[] data, String keyStorePath, String alias, String password) throws Exception {
		// 取得私钥
		PrivateKey privateKey = getPrivateKey(keyStorePath, alias, password);
		Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		int inputLen = data.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段加密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
				cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(data, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_ENCRYPT_BLOCK;
		}
		byte[] encryptedData = out.toByteArray();
		out.close();
		return encryptedData;
	}

	public static byte[] encryptFileByPrivateKey(String filePath, String keyStorePath, String alias, String password) throws Exception {
		byte[] data = fileToByte(filePath);
		return encryptByPrivateKey(data, keyStorePath, alias, password);
	}

	public static void encryptFileByPrivateKey(String srcFilePath, String destFilePath, String keyStorePath, String alias, String password) throws Exception {
		// 取得私钥
		PrivateKey privateKey = getPrivateKey(keyStorePath, alias, password);
		Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		File srcFile = new File(srcFilePath);
		FileInputStream in = new FileInputStream(srcFile);
		File destFile = new File(destFilePath);
		if (!destFile.getParentFile().exists()) {
			destFile.getParentFile().mkdirs();
		}
		destFile.createNewFile();
		OutputStream out = new FileOutputStream(destFile);
		byte[] data = new byte[MAX_ENCRYPT_BLOCK];
		byte[] encryptedData; // 加密块
		while (in.read(data) != -1) {
			encryptedData = cipher.doFinal(data);
			out.write(encryptedData, 0, encryptedData.length);
			out.flush();
		}
		out.close();
		in.close();
	}

	public static String encryptFileToBase64ByPrivateKey(String filePath, String keyStorePath, String alias, String password) throws Exception {
		byte[] encryptedData = encryptFileByPrivateKey(filePath, keyStorePath, alias, password);
		return Base64Utils.encode(encryptedData);
	}

	public static byte[] decryptByPrivateKey(byte[] encryptedData, String keyStorePath, String alias, String password) throws Exception {
		// 取得私钥
		PrivateKey privateKey = getPrivateKey(keyStorePath, alias, password);
		Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		// 解密byte数组最大长度限制: 128
		int inputLen = encryptedData.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段解密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
				cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_DECRYPT_BLOCK;
		}
		byte[] decryptedData = out.toByteArray();
		out.close();
		return decryptedData;
	}

	public static byte[] encryptByPublicKey(byte[] data, String certificatePath) throws Exception {
		// 取得公钥
		PublicKey publicKey = getPublicKey(certificatePath);
		Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		int inputLen = data.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段加密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
				cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(data, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_ENCRYPT_BLOCK;
		}
		byte[] encryptedData = out.toByteArray();
		out.close();
		return encryptedData;
	}

	public static byte[] decryptByPublicKey(byte[] encryptedData, String certificatePath) throws Exception {
		PublicKey publicKey = getPublicKey(certificatePath);
		Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		int inputLen = encryptedData.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段解密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
				cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_DECRYPT_BLOCK;
		}
		byte[] decryptedData = out.toByteArray();
		out.close();
		return decryptedData;
	}

	public static void decryptFileByPublicKey(String srcFilePath, String destFilePath, String certificatePath) throws Exception {
		PublicKey publicKey = getPublicKey(certificatePath);
		Cipher cipher = Cipher.getInstance(publicKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		File srcFile = new File(srcFilePath);
		FileInputStream in = new FileInputStream(srcFile);
		File destFile = new File(destFilePath);
		if (!destFile.getParentFile().exists()) {
			destFile.getParentFile().mkdirs();
		}
		destFile.createNewFile();
		OutputStream out = new FileOutputStream(destFile);
		byte[] data = new byte[MAX_DECRYPT_BLOCK];
		byte[] decryptedData; // 解密块
		while (in.read(data) != -1) {
			decryptedData = cipher.doFinal(data);
			out.write(decryptedData, 0, decryptedData.length);
			out.flush();
		}
		out.close();
		in.close();
	}

	public static byte[] sign(byte[] data, String keyStorePath, String alias, String password) throws Exception {
		// 获得证书
		X509Certificate x509Certificate = (X509Certificate) getCertificate(keyStorePath, alias, password);
		// 获取私钥
		KeyStore keyStore = getKeyStore(keyStorePath, password);
		// 取得私钥
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
		// 构建签名
		Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
		signature.initSign(privateKey);
		signature.update(data);
		return signature.sign();
	}

	public static String signToBase64(byte[] data, String keyStorePath, String alias, String password) throws Exception {
		return Base64Utils.encode(sign(data, keyStorePath, alias, password));
	}

	public static String signFileToBase64WithEncrypt(String filePath, String keyStorePath, String alias, String password) throws Exception {
		byte[] encryptedData = encryptFileByPrivateKey(filePath, keyStorePath, alias, password);
		return signToBase64(encryptedData, keyStorePath, alias, password);
	}
	
	public static byte[] generateFileSign(String filePath, String keyStorePath, String alias, String password) throws Exception {
		byte[] sign = new byte[0];
		// 获得证书
		X509Certificate x509Certificate = (X509Certificate) getCertificate(keyStorePath, alias, password);
		// 获取私钥
		KeyStore keyStore = getKeyStore(keyStorePath, password);
		// 取得私钥
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
		// 构建签名
		Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
		signature.initSign(privateKey);
		File file = new File(filePath);
		if (file.exists()) {
			FileInputStream in = new FileInputStream(file);
			byte[] cache = new byte[CACHE_SIZE];
			int nRead = 0;
			while ((nRead = in.read(cache)) != -1) {
				signature.update(cache, 0, nRead);
			}
			in.close();
			sign = signature.sign();
		}
		return sign;
	}

	public static String signFileToBase64(String filePath, String keyStorePath, String alias, String password) throws Exception {
		return Base64Utils.encode(generateFileSign(filePath, keyStorePath, alias, password));
	}

	public static boolean verifySign(byte[] data, String sign, String certificatePath) throws Exception {
		// 获得证书
		X509Certificate x509Certificate = (X509Certificate) getCertificate(certificatePath);
		// 获得公钥
		PublicKey publicKey = x509Certificate.getPublicKey();
		// 构建签名
		Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
		signature.initVerify(publicKey);
		signature.update(data);
		return signature.verify(Base64Utils.decode(sign));
	}

	public static boolean validateFileSign(String filePath, String sign, String certificatePath) throws Exception {
		boolean result = false;
		// 获得证书
		X509Certificate x509Certificate = (X509Certificate) getCertificate(certificatePath);
		// 获得公钥
		PublicKey publicKey = x509Certificate.getPublicKey();
		// 构建签名
		Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
		signature.initVerify(publicKey);
		File file = new File(filePath);
		if (file.exists()) {
			byte[] decodedSign = Base64Utils.decode(sign);
			FileInputStream in = new FileInputStream(file);
			byte[] cache = new byte[CACHE_SIZE];
			int nRead = 0;
			while ((nRead = in.read(cache)) != -1) {
				signature.update(cache, 0, nRead);
			}
			in.close();
			result = signature.verify(decodedSign);
		}
		return result;
	}

	public static boolean verifyBase64Sign(String base64String, String sign, String certificatePath) throws Exception {
		byte[] data = Base64Utils.decode(base64String);
		return verifySign(data, sign, certificatePath);
	}

	public static boolean verifyBase64SignWithDecrypt(String base64String, String sign, String certificatePath) throws Exception {
		byte[] encryptedData = Base64Utils.decode(base64String);
		byte[] data = decryptByPublicKey(encryptedData, certificatePath);
		return verifySign(data, sign, certificatePath);
	}

	public static boolean verifyFileSignWithDecrypt(String encryptedFilePath, String sign, String certificatePath) throws Exception {
		byte[] encryptedData = fileToByte(encryptedFilePath);
		byte[] data = decryptByPublicKey(encryptedData, certificatePath);
		return verifySign(data, sign, certificatePath);
	}

	public static boolean verifyCertificate(Certificate certificate) {
		return verifyCertificate(new Date(), certificate);
	}

	public static boolean verifyCertificate(Date date, Certificate certificate) {
		boolean isValid = true;
		try {
			X509Certificate x509Certificate = (X509Certificate) certificate;
			x509Certificate.checkValidity(date);
		} catch (Exception e) {
			isValid = false;
		}
		return isValid;
	}

	public static boolean verifyCertificate(Date date, String certificatePath) {
		Certificate certificate;
		try {
			certificate = getCertificate(certificatePath);
			return verifyCertificate(certificate);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public static boolean verifyCertificate(Date date, String keyStorePath, String alias, String password) {
		Certificate certificate;
		try {
			certificate = getCertificate(keyStorePath, alias, password);
			return verifyCertificate(certificate);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public static boolean verifyCertificate(String keyStorePath, String alias, String password) {
		return verifyCertificate(new Date(), keyStorePath, alias, password);
	}

	public static boolean verifyCertificate(String certificatePath) {
		return verifyCertificate(new Date(), certificatePath);
	}

	public static byte[] fileToByte(String filePath) throws Exception {
		byte[] data = new byte[0];
		File file = new File(filePath);
		if (file.exists()) {
			FileInputStream in = new FileInputStream(file);
			ByteArrayOutputStream out = new ByteArrayOutputStream(2048);
			byte[] cache = new byte[CACHE_SIZE];
			int nRead = 0;
			while ((nRead = in.read(cache)) != -1) {
				out.write(cache, 0, nRead);
				out.flush();
			}
			out.close();
			in.close();
			data = out.toByteArray();
		}
		return data;
	}

	public static void byteArrayToFile(byte[] bytes, String filePath) throws Exception {
		InputStream in = new ByteArrayInputStream(bytes);
		File destFile = new File(filePath);
		if (!destFile.getParentFile().exists()) {
			destFile.getParentFile().mkdirs();
		}
		destFile.createNewFile();
		OutputStream out = new FileOutputStream(destFile);
		byte[] cache = new byte[CACHE_SIZE];
		int nRead = 0;
		while ((nRead = in.read(cache)) != -1) {
			out.write(cache, 0, nRead);
			out.flush();
		}
		out.close();
		in.close();
	}

}