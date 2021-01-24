package src;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server {
    private final static String SERVERID = "Alice";
    private final static String SECRET_KEY = "secret_key";
    private final static int PORT = 1234;

    public static void main(String[] arg) {


        try (ServerSocket listener = new ServerSocket(PORT)) {
            System.out.println("The Server is running...");
            ExecutorService pool = Executors.newFixedThreadPool(20);
            while (true) {
                pool.execute(new ServerRun(listener.accept()));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class ServerRun implements Runnable {
        private final Socket socket;

        ServerRun(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            System.out.println("Connected: " + socket);

            try {
                Scanner in = new Scanner(socket.getInputStream());
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
//
                while (in.hasNextLine()) {
                    int cid = new Random().nextInt(100 - 10) + 10;
                    System.out.println("cid = " + cid);

                    String message = in.nextLine();

                    // id | H | T1 | signM1
                    System.out.println("message = " + message);
                    String[] m1 = message.split("\\|");
                    System.out.println("Arrays.toString(m1) = " + Arrays.toString(m1));


                    long T2 = System.currentTimeMillis();
                    System.out.println("T2 = " + T2);

                    // check if time <= 5 detik
                    if (T2 - Long.parseLong(m1[2]) <= 5000) {

                        System.out.println("**** VALID ****");

                        String Hid = Fungsi.encryptThisString(String.valueOf(m1[0]));
                        System.out.println("Hid = " + Hid);
//
                        String Hpw = Fungsi.encryptThisString(SECRET_KEY);
                        System.out.println("Hpw = " + Hpw);

                        // H(HID|HPW|User-Rand-ID|T1)
                        String HC = Fungsi.encryptThisString(Hid + Hpw + m1[0] + m1[2]);
                        System.out.println("HC = " + HC);

                        String N1 = Fungsi.xor(HC, m1[1]);
                        System.out.println("N1 = " + N1);

                        // H[User-Rand-ID, H(HID|HPW|User-Rand-ID|T1) ,N1,T1]
                        String HM1 = Fungsi.encryptThisString(m1[0] + HC + N1 + m1[2]);
                        System.out.println("HM1 = " + HM1);


                        if (HM1.equals(m1[3])) {

                            System.out.println("**** VALID ****");

                            long T3 = System.currentTimeMillis();
                            System.out.println("T3 = " + T3);

                            // H(CID|HID|HPW|User-Rand-ID|T1|T3)
                            String H = Fungsi.encryptThisString(cid + Hid + Hpw + m1[0] + m1[2] + T3);
                            System.out.println("H = " + H);

                            String N2 = Fungsi.xor(H, H);
                            System.out.println("N2 = " + N2);

                            // H(CID|HPW|N1|N2|T1|T2)
                            String simKey = Fungsi.encryptThisString(cid + Hpw + N1 + N2 + m1[2] + T3);
                            System.out.println("simKey = " + simKey);

                            String signM2 = Fungsi.encryptThisString(cid + H + N2 + T3);
                            System.out.println("signM2 = " + signM2);

                            // cid | H | T2 | signM2
                            String M2 = cid + "|" + H + "|" + T3 + "|" + signM2;
                            System.out.println("M1 = " + M2);

                            System.out.println("Sennding to Client " + M2);
                            out.println(M2);


                            message = in.nextLine();

                            if (message.equals(Fungsi.ERROR)) {
                                System.out.println("**** NOT VALID ****");
                                out.println(Fungsi.ERROR);
                            } else {
                                System.out.println("**** SECRET KEY VALID ****");

                                // Receive M3 = id | hashApp | T5 | pubKeyUstr
                                String[] m3 = message.split("\\|");
                                System.out.println("Arrays.toString(m3) = " + Arrays.toString(m3));

                                long T4 = System.currentTimeMillis();
                                System.out.println("T4 = " + T4);

                                KeyPair pairServer = Fungsi.generateKeyPair();
                                System.out.println("pairServer = " + pairServer);
                                PublicKey pubKeyS = pairServer.getPublic();
                                System.out.println("pubKeyS = " + pubKeyS);
                                PrivateKey privKeyS = pairServer.getPrivate();
                                System.out.println("privKeyS = " + privKeyS);

                                String pubKeySstr = Base64.getEncoder().encodeToString(pubKeyS.getEncoded());
                                System.out.println("pubKeySstr = " + pubKeySstr);
                                String privKeySstr = Base64.getEncoder().encodeToString(privKeyS.getEncoded());
                                System.out.println("privKeySstr = " + privKeySstr);

                                String hashAck = Fungsi.hash(cid + pubKeySstr + m1[0]);
                                System.out.println("hashAck = " + hashAck);
//                            String signU_CA = Fungsi.encrypt(hashAck, pubKeyU);

                                // send M4 = cid | hashAck | T4 | pubKeySstr
                                String M4 = cid + "|" + hashAck + "|" + T4 + "|" + pubKeySstr;
                                System.out.println("M4 = " + M4);
                                out.println(M4);


                                long T5 = System.currentTimeMillis();
                                System.out.println("T5 = " + T5);

                                if (T5 - Long.parseLong(m3[2]) <= 5000) {
                                    String hashApp = Fungsi.hash(m3[0] + m3[3] + cid);
                                    System.out.println("hashAck = " + hashAck);
                                    System.out.println("hashApp = " + hashApp);

                                    if (hashApp.equals(m3[1])) {
                                        System.out.println("**** VALID ****");

//                                        String hashSignS_CA = Fungsi.hash(serverPublic_Cert[0] + serverPublic_Cert[1] + id + pubKeyUstr);
                                        String hashSignS_CA = Fungsi.hash(cid + pubKeySstr + m3[0] + m3[3]);
                                        System.out.println("hashSignS_CA = " + hashSignS_CA);

                                        //Convert StringBase64 to Public Key
                                        byte[] publicBytes = Base64.getDecoder().decode(m3[3]);
                                        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
                                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                                        PublicKey pubKeyU = keyFactory.generatePublic(keySpec);

                                        String signS_CA = Fungsi.encrypt(hashSignS_CA, pubKeyU);
                                        System.out.println("signS_CA = " + signS_CA);

                                        String serverPublic_Cert = cid + "|" + pubKeySstr + "|" + m3[3] + "|" + m3[0] + "|" + signS_CA;
                                        System.out.println("serverPublic_Cert = " + serverPublic_Cert);

                                        // send serverPublic_Cert = id | pubKeyUstr | pubKeyCstr | cloudID | signS_CA;
                                        out.println(serverPublic_Cert);

                                        message = in.nextLine();
                                        String[] userPublic_Cert = message.split("\\|");
                                        String hashSignU_CA = Fungsi.hash(userPublic_Cert[0] + userPublic_Cert[1] + cid + pubKeySstr);
                                        System.out.println("hashSignU_CA = " + hashSignU_CA);
                                        System.out.println("Fungsi.decrypt(userPublic_Cert[4], privKeyS) = " + Fungsi.decrypt(userPublic_Cert[4], privKeyS));

                                        if (hashSignU_CA.equals(Fungsi.decrypt(userPublic_Cert[4], privKeyS))) {
                                            System.out.println(" Secret Key VALID");
                                        } else {
                                            System.out.println(" Secret Key NOTVALID");
                                        }
                                    } else {
                                        System.out.println("Wrong secret key!");
                                        out.println(Fungsi.ERROR);
                                    }
                                } else {
                                    System.out.println("Error Timeout!");
                                    out.println(Fungsi.ERROR);
                                }
                            }
                        } else {
                            System.out.println("**** NOT VALID ****");
                            System.out.println("Sennding to Client " + Fungsi.ERROR);
                            out.println(Fungsi.ERROR);
                        }
                    } else {
                        System.out.println("**** NOT VALID ****");
                        System.out.println("Sennding to Client " + Fungsi.ERROR);
                        out.println(Fungsi.ERROR);
                    }
                }
            } catch (Exception e) {
                System.out.println("Error:" + socket);
            } finally {
                try {
                    socket.close();
                } catch (IOException ignored) {
                }
                System.out.println("Closed: " + socket);
            }
        }
    }
}