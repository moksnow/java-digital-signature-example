###1.Generate key pair for Digital Signature Common Approach
####1-1.Generate key pair as keystore(use in source for signing)
```shell
keytool -genkeypair -alias sourceKeyPair -keyalg RSA -keysize 2048 -dname "CN=Mok" -validity 365 -storetype PKCS12 -keystore source_keystore.p12 -storepass samplePassword
```

####1-2.Export public key from key pair
```shell
keytool -exportcert -alias sourceKeyPair -storetype PKCS12 -keystore source_keystore.p12 -file source_certificate.cer -rfc -storepass samplePassword
```

####1-3.import public key to keystore(use in destination for verify message and verify sign)
```shell
keytool -importcert -alias destinationKeyPair -storetype PKCS12 -keystore destination_keystore.p12 -file source_certificate.cer -rfc -storepass samplePassword
```

####2.Generate key pair for Digital Signature CMS Approach
```shell
openssl req -new -x509 -sha256 -newkey rsa:2048 -nodes -keyout key.pem -days 3650 -out cert.pem
```