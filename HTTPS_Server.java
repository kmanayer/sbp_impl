package delftstack;

import com.sun.net.httpserver.*;

import javax.crypto.SecretKey;
import javax.net.ssl.*;
//import javax.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.security.KeyStore;

public class HTTPS_Server {

    public static class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange x) throws IOException {
            String Response = "This is the response from delftstack";
            HttpsExchange xs = (HttpsExchange) x;
            //DatatypeConverter.printHexBinary(xs.getSSLSession().getId()); // byte array has 32 bytes
            printByteArray(xs.getSSLSession().getId());
            try {
                Class<?> c = Class.forName("sun.security.ssl.SSLSessionImpl");
                Field masterSecretField = c.getDeclaredField("masterSecret");
                SecretKey k = (SecretKey)masterSecretField.get(xs.getSSLSession());
                printByteArray(k.getEncoded());
            } catch (Exception e) {
                System.out.println(e.getStackTrace().toString());
            }
            x.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
            x.sendResponseHeaders(200, Response.getBytes().length);
            OutputStream Output_Stream = x.getResponseBody();
            Output_Stream.write(Response.getBytes());
            Output_Stream.close();
        }
    }

    private static void printByteArray(byte[] a) {
        for (int i = 0; i < a.length; i++) {
            System.out.print((int)a[i] + " ");
        }
        System.out.println();
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
            FileInputStream Input_Stream = new FileInputStream("testkey.jks");
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