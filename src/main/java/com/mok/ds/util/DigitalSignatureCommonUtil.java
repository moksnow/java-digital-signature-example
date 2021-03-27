package com.mok.ds.util;

import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * @author m_khandan
 * Date: 3/27/2021
 * Time: 1:37 PM
 */
public class DigitalSignatureCommonUtil {

    private static final String DEFAULT_PASSWORD = "samplePassword";


    public static String createFilePath() {
        File dir = new File("input");
        if (!dir.exists()) dir.mkdir();
        return dir.getAbsolutePath();
    }
    
    private static BigInteger checksum(Object obj) throws IOException, NoSuchAlgorithmException {

        if (obj == null) {
            return BigInteger.ZERO;
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(obj);
        oos.close();

        MessageDigest m = MessageDigest.getInstance("SHA-256");
        m.update(baos.toByteArray());

        return new BigInteger(1, m.digest());
    }

    public static byte[] sign(String message) throws Exception {
        byte[] messageBytes = message.getBytes();

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = md.digest(messageBytes);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, getPrivate("source_keystore.p12"));
        return cipher.doFinal(messageHash);
    }

    public static boolean verifyMessage(byte[] digitalSignature, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, getPublic("destination_keystore.p12"));
        byte[] decryptedMessageHash = cipher.doFinal(digitalSignature);

        byte[] messageBytes = message.getBytes();

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] newMessageHash = md.digest(messageBytes);

        return Arrays.equals(decryptedMessageHash, newMessageHash);

    }

    //Method to retrieve the Private Key from a file
    public static PrivateKey getPrivate(String filename) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(createFilePath().concat(File.separator).concat(filename)), DEFAULT_PASSWORD.toCharArray());
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("sourceKeyPair", DEFAULT_PASSWORD.toCharArray());
        return privateKey;
    }

    //Method to retrieve the Public Key from a file
    public static PublicKey getPublic(String filename) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream(createFilePath().concat(File.separator).concat(filename)), DEFAULT_PASSWORD.toCharArray());
        java.security.cert.Certificate certificate = keyStore.getCertificate("destinationKeyPair");
        PublicKey publicKey = certificate.getPublicKey();
        return publicKey;
    }

    //Method to retrieve the Public Key from a file
    public static X509Certificate getCertificate(String filename) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new FileInputStream("MyKeys/".concat(filename)), DEFAULT_PASSWORD.toCharArray());
        Certificate certificate = keyStore.getCertificate("destinationKeyPair");
        X509Certificate certificate1 = (X509Certificate) certificate;
        return certificate1;
    }

    public static RSAPublicKey readPublicKey(String file) throws Exception {
        String key = new String(Files.readAllBytes(Paths.get(file)), Charset.defaultCharset());

        String publicKeyPEM = key
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");

        byte[] encoded = Base64.decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    public static X509Certificate readCertificate(String file) throws Exception {
        String key = new String(Files.readAllBytes(Paths.get(file)), Charset.defaultCharset());


        String publicKeyPEM = key
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replaceAll("\n", "")
                .replace("-----END CERTIFICATE-----", "");

        byte[] certificateData = Base64.decode(publicKeyPEM);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
        return certificate;
    }


    public static RSAPrivateKey readPrivateKey(String file) throws Exception {
        String key = new String(Files.readAllBytes(Paths.get(file)), Charset.defaultCharset());

        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replaceAll("\n", "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] encoded = Base64.decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

}
