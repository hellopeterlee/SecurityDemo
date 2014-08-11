1.生成keypari(默认算法为DSA,这里要指定为RSA,方便后面的加密解密):
keytool -genkeypair -validity 365 -alias forhanwan -keyalg RSA

2.导出证书,证书只包含公钥
keytool -exportcert -alias forhanwan -file hanwan.cer