package delftstack;

import com.sun.net.httpserver.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
//import javax.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.HttpCookie;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

public class HTTPS_Server {

    private static final String KEY_STORE = "mySecondTestKeyStore.jks";

    private static final String KPS;

    static {
        try {
            // do something similar to generateIV and generateNewSessionToken
            SecretKey Kp =  KeyGenerator.getInstance("AES").generateKey(); // 16
            KPS = Base64.getEncoder().encodeToString(Kp.getEncoded()); // 24
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static List<String> sessionTokens = new ArrayList<>();

    public static class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange x) throws IOException {

            try {
                SecretKey clientKey = getClientSpecificKey(x);

                List<String> cookie = x.getRequestHeaders().get("Cookie");
                if (null != cookie) {
                    String encryptedToken = HttpCookie.parse(cookie.get(0)).get(0).getValue();
                    String token = Optional.ofNullable(decrypt(encryptedToken, clientKey)).orElse("decryption failed");
                    String response = "did you give us the right token on the right channel? " + sessionTokens.contains(token) + "\n";
                    response = response.concat("your encrypted token: " + encryptedToken + "\n");
                    response = response.concat("your decrypted token: " + token + "\n");
                    response = response.concat("your client key: " + Base64.getEncoder().encodeToString(clientKey.getEncoded()) + "\n");
                    x.sendResponseHeaders(200, response.getBytes().length);
                    x.getResponseHeaders().add("Content-Type", "text/html");
                    OutputStream Output_Stream = x.getResponseBody();
                    Output_Stream.write(response.getBytes());
                    Output_Stream.close();
                } else {
                    String token = generateNewSessionToken();
                    sessionTokens.add(token);
                    String encryptedToken = encrypt(token, clientKey);
                    HttpCookie newCookie = new HttpCookie("session_token", encryptedToken);
                    newCookie.setComment("This is a test session token");
                    //newCookie.setDomain("localhost");
                    newCookie.setPath("/test");

                    String response = "This is the response from the server, we didn't find a cookie so we are providing you with one here\n"; // need to inject malicious code here
                    response = response.concat("your encrypted cookie: " + newCookie + "\n");
                    response = response.concat("your plain session token: " + token + "\n");
                    response = response.concat("your client key: " + Base64.getEncoder().encodeToString(clientKey.getEncoded()) + "\n");
                    x.sendResponseHeaders(200, response.getBytes().length);
                    x.getResponseHeaders().add("Content-Type", "text/html");
                    x.getResponseHeaders().add("Set-Cookie", newCookie.toString());
                    OutputStream Output_Stream = x.getResponseBody();
                    Output_Stream.write(response.getBytes());
                    Output_Stream.close();
                }

            } catch (Exception e) {
                System.out.println(e.getMessage());
                throw new RuntimeException(e);
            }
        }

        private  SecretKey getClientSpecificKey(HttpExchange x) throws Exception {
            HttpsExchange xs = (HttpsExchange) x;
            Class<?> c = Class.forName("sun.security.ssl.SSLSessionImpl");
            Field masterSecretField = c.getDeclaredField("resumptionMasterSecret");
            masterSecretField.setAccessible(true);
            SecretKey k = (SecretKey)masterSecretField.get(xs.getSSLSession()); // 48
            String ks = Base64.getEncoder().encodeToString(k.getEncoded()); // 64
            String kcs = KPS.concat(ks); // 88
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(kcs.getBytes()); // 32 after digest
            String kcsh = Base64.getEncoder().encodeToString(md.digest()); // 44
            byte[] kcb = Base64.getDecoder().decode(kcsh);
            return new SecretKeySpec(kcb, 0, kcb.length, "AES");
        }

        private static String generateNewSessionToken() {
            byte[] token = new byte[16];
            new SecureRandom().nextBytes(token);
            return Base64.getEncoder().encodeToString(token);
        }

        //https://www.baeldung.com/java-aes-encryption-decryption
        private static String encrypt(String input, SecretKey key) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = generateIV(); // 16
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] cipherText = cipher.doFinal(input.getBytes()); // 32
            String cipherTextString = Base64.getEncoder().encodeToString(cipherText); // 44
            String ivString = Base64.getEncoder().encodeToString(iv.getIV()); // 24
            return ivString.concat(cipherTextString);
        }

        private static IvParameterSpec generateIV() {
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            return new IvParameterSpec(iv);
        }

        private static String decrypt(String input, SecretKey key) {
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                byte[] iv = Base64.getDecoder().decode(input.substring(0,24));
                byte[] cipherText = Base64.getDecoder().decode(input.substring(24));
                cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                return new String(cipher.doFinal(cipherText));
            } catch (Exception e) {
                return null;
            }
        }


    }



    public static void main(String[] args) throws Exception {

        try {
            // setup the socket address
            InetSocketAddress Inet_Address = new InetSocketAddress(9000);

            //initialize the HTTPS server
            HttpsServer HTTPS_Server = HttpsServer.create(Inet_Address, 0);
            SSLContext SSL_Context = SSLContext.getInstance("TLS");

            // initialise the keystore
            char[] Password = "password".toCharArray();
            KeyStore Key_Store = KeyStore.getInstance("JKS");
            FileInputStream Input_Stream = new FileInputStream(KEY_STORE);
            Key_Store.load(Input_Stream, Password);

            // setup the key manager factory
            KeyManagerFactory Key_Manager = KeyManagerFactory.getInstance("SunX509");
            Key_Manager.init(Key_Store, Password);

            // setup the trust manager factory
            TrustManagerFactory Trust_Manager = TrustManagerFactory.getInstance("SunX509");
            Trust_Manager.init(Key_Store);

            // setup the HTTPS context and parameters
            SSL_Context.init(Key_Manager.getKeyManagers(), Trust_Manager.getTrustManagers(), null);
            HTTPS_Server.setHttpsConfigurator(new HttpsConfigurator(SSL_Context) {
                public void configure(HttpsParameters params) {
                    try {
                        // initialise the SSL context
                        SSLContext SSL_Context = getSSLContext();
                        SSLEngine SSL_Engine = SSL_Context.createSSLEngine();
                        params.setNeedClientAuth(false);
                        params.setCipherSuites(SSL_Engine.getEnabledCipherSuites());
                        params.setProtocols(SSL_Engine.getEnabledProtocols());

                        // Set the SSL parameters
                        SSLParameters SSL_Parameters = SSL_Context.getSupportedSSLParameters();
                        params.setSSLParameters(SSL_Parameters);
                        System.out.println("The HTTPS server is connected");

                    } catch (Exception ex) {
                        System.out.println("Failed to create the HTTPS port");
                    }
                }
            });
            HTTPS_Server.createContext("/test", new MyHandler());
            HTTPS_Server.setExecutor(null); // creates a default executor
            HTTPS_Server.start();

        } catch (Exception exception) {
            System.out.println("Failed to create HTTPS server on port " + 9000 + " of localhost");
            exception.printStackTrace();

        }
    }

}