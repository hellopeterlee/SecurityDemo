1.生成keypari(默认算法为DSA):
keytool -genkeypair -alias forhanwan

2.导出证书,证书只包含公钥
keytool -exportcert -alias forhanwan -file c:\forhanwan.cer