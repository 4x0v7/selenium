/*
 * Copyright 2014 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package org.openqa.selenium.grid.server;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.security.auth.x500.X500Principal;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.CharBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.regex.Pattern.CASE_INSENSITIVE;
import static javax.crypto.Cipher.DECRYPT_MODE;

// import org.bouncycastle.asn1.ASN1InputStream;
// import org.bouncycastle.asn1.DERObject;
// import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
// import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
// import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
// import java.security.PrivateKey;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

public final class SslKeystoreCreator
{
    private static final Pattern CERT_PATTERN = Pattern.compile(
            "-+BEGIN\\s+.*CERTIFICATE[^-]*-+(?:\\s|\\r|\\n)+" + // Header
                    "([a-z0-9+/=\\r\\n]+)" +                    // Base64 text
                    "-+END\\s+.*CERTIFICATE[^-]*-+",            // Footer
            CASE_INSENSITIVE);

    private static final Pattern RSA_KEY_PATTERN = Pattern.compile(
            "-+BEGIN\\s+RSA\\s+PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+" + // Header
                    "([a-z0-9+/=\\r\\n]+)" +                       // Base64 text
                    "-+END\\s+RSA\\s+PRIVATE\\s+KEY[^-]*-+",            // Footer
            CASE_INSENSITIVE);

    private SslKeystoreCreator() {}

    // public static KeyStore loadTrustStore(File certificateChainFile)
    //         throws IOException, GeneralSecurityException
    // {
    //     KeyStore keyStore = KeyStore.getInstance("JKS");
    //     keyStore.load(null, null);

    //     List<X509Certificate> certificateChain = readCertificateChain(certificateChainFile);
    //     for (X509Certificate certificate : certificateChain) {
    //         X500Principal principal = certificate.getSubjectX500Principal();
    //         keyStore.setCertificateEntry(principal.getName("RFC2253"), certificate);
    //     }
    //     return keyStore;
    // }

    public static KeyStore loadKeyStore(File certificateChainFile, File privateKeyFile)
            throws IOException, GeneralSecurityException
    {
        // PKCS8EncodedKeySpec encodedKeySpec = readPrivateKey(privateKeyFile, keyPassword);

        PrivateKey privateKey = readPrivateKey(privateKeyFile);

        List<X509Certificate> certificateChain = readCertificateChain(certificateChainFile);
        if (certificateChain.isEmpty()) {
            throw new CertificateException("Certificate file does not contain any certificates: " + certificateChainFile);
        }

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry("key", privateKey, ("").toCharArray(), certificateChain.stream().toArray(Certificate[]::new));
        return keyStore;
    }

    private static List<X509Certificate> readCertificateChain(File certificateChainFile)
            throws IOException, GeneralSecurityException
    {
        String contents = readFile(certificateChainFile);

        Matcher matcher = CERT_PATTERN.matcher(contents);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certificates = new ArrayList<>();

        int start = 0;
        while (matcher.find(start)) {
            byte[] buffer = base64Decode(matcher.group(1));
            certificates.add((X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(buffer)));
            start = matcher.end();
        }

        return certificates;
    }

    private static PrivateKey readPrivateKey(File keyFile) throws IOException, GeneralSecurityException {
        String content = readFile(keyFile);

        Matcher matcher = RSA_KEY_PATTERN.matcher(content);
        if (!matcher.find()) {
            throw new KeyStoreException("found no private key: " + keyFile);
        }
        byte[] encodedKey = base64Decode(matcher.group(1));

            try {
                PrivateKey privateKey = readRSAPrivateKeyPKCS1PEM(encodedKey);
                return privateKey;
            } catch (Exception e) {
                // TODO
            }
        return null;
    }

    private static PrivateKey readRSAPrivateKeyPKCS1PEM(byte[] encodedKey) throws Exception {

        byte[] bytes = encodedKey;

        DerInputStream derReader = new DerInputStream(bytes);
        DerValue[] seq = derReader.getSequence(0);
        // skip version seq[0];
        BigInteger modulus    = seq[1].getBigInteger();
        BigInteger publicExp  = seq[2].getBigInteger();
        BigInteger privateExp = seq[3].getBigInteger();
        BigInteger prime1     = seq[4].getBigInteger();
        BigInteger prime2     = seq[5].getBigInteger();
        BigInteger exp1       = seq[6].getBigInteger();
        BigInteger exp2       = seq[7].getBigInteger();
        BigInteger crtCoef    = seq[8].getBigInteger();

        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    private static byte[] base64Decode(String base64)
    {
        return Base64.getMimeDecoder().decode(base64.getBytes(US_ASCII));
    }

    private static String readFile(File file)
            throws IOException
    {
        try (Reader reader = new InputStreamReader(new FileInputStream(file), US_ASCII)) {
            StringBuilder stringBuilder = new StringBuilder();

            CharBuffer buffer = CharBuffer.allocate(2048);
            while (reader.read(buffer) != -1) {
                buffer.flip();
                stringBuilder.append(buffer);
                buffer.clear();
            }
            return stringBuilder.toString();
        }
    }
}
