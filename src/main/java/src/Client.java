package src;

import java.io.PrintWriter;
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

public class Client {
    //    private final static String CLIENTID = "Bob";
    private final static int PORT = 1234;

    public static void main(String[] args) {
        System.out.println("The Client is running...");


        try (Socket socket = new Socket("localhost", PORT)) {
            Scanner in = new Scanner(socket.getInputStream());
            Scanner scanner = new Scanner(System.in);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            System.out.print("Check Secret Key : ");
            while (scanner.hasNextLine()) {
                String clientSecretKey = scanner.nextLine();

                //                String clientSecretKey = "key";

                int id = new Random().nextInt(100 - 10) + 10;
                System.out.println("id = " + id);

                String Hid = Fungsi.encryptThisString(String.valueOf(id));
                System.out.println("Hid = " + Hid);

                String Hpw = Fungsi.encryptThisString(clientSecretKey);
                System.out.println("Hpw = " + Hpw);

                long T1 = System.currentTimeMillis();
                System.out.println("T1 = " + T1);

                String H = Fungsi.encryptThisString(Hid + Hpw + id + T1);
                System.out.println("H = " + H);

                String N1 = Fungsi.xor(H, H);
                System.out.println("N1 = " + N1);

                String signM1 = Fungsi.encryptThisString(id + H + N1 + T1);
                System.out.println("signM1 = " + signM1);

                // id | H | T1 | signM1
                String M1 = id + "|" + H + "|" + T1 + "|" + signM1;
                System.out.println("M1 = " + M1);

                String[] m = M1.split("\\|");
                System.out.println("Arrays.toString(m) = " + Arrays.toString(m));

                out.println(M1);

//                Fungsi.delay(2000);
                String message = in.nextLine();
                if (!message.equals(Fungsi.ERROR)) {
                    System.out.println("**** VALID ****");
                    System.out.println("message = " + message);

                    // cid | H | T2 | signM2
                    String[] m2 = message.split("\\|");
                    System.out.println("Arrays.toString(m2) = " + Arrays.toString(m2));

                    long T4 = System.currentTimeMillis();
                    System.out.println("T4 = " + T4);

                    // check if time <= 5 detik
                    if (T4 - Long.parseLong(m2[2]) <= 5000) {
                        System.out.println("**** VALID ****");

                        // H(CID|HID|HPW|User-Rand-ID|T1|T3)
                        String HU = Fungsi.encryptThisString(m2[0] + Hid + Hpw + id + T1 + m2[2]);
                        System.out.println("HU = " + HU);

                        // xor(HU, M2b)
                        String N2 = Fungsi.xor(HU, m2[1]);
                        System.out.println("N2 = " + N2);

                        // H[CID, H(CID|HID|HPW|User-Rand-ID|T1|T3),N2,T3]
                        String HM2 = Fungsi.encryptThisString(m2[0] + HU + N2 + m2[2]);
                        System.out.println("HM2 = " + HM2);

                        if (HM2.equals(m2[3])) {
                            System.out.println("**** VALID ****");

                            long T5 = System.currentTimeMillis();
                            System.out.println("T5 = " + T5);

                            KeyPair pairUser = Fungsi.generateKeyPair();
                            System.out.println("pairUser = " + pairUser);
                            PublicKey pubKeyU = pairUser.getPublic();
                            System.out.println("pubKeyU = " + pubKeyU);
                            PrivateKey privKeyU = pairUser.getPrivate();
                            System.out.println("privKeyU = " + privKeyU);

                            String pubKeyUstr = Base64.getEncoder().encodeToString(pubKeyU.getEncoded());
                            System.out.println("pubKeyUstr = " + pubKeyUstr);
                            String privKeyUstr = Base64.getEncoder().encodeToString(privKeyU.getEncoded());
                            System.out.println("privKeyUstr = " + privKeyUstr);

                            String hashApp = Fungsi.hash(id + pubKeyUstr + m2[0]);
                            System.out.println("hashApp = " + hashApp);
//                            String signU_CA = Fungsi.encrypt(hashApp, pubKeyU);

                            // send M3 = id | hashApp | T5 | pubKeyUstr
                            String M3 = id + "|" + hashApp + "|" + T5 + "|" + pubKeyUstr;
                            System.out.println("M3 = " + M3);
                            out.println(M3);


                            message = in.nextLine();
                            if (!message.equals(Fungsi.ERROR)) {
                                // cid | H | T2 | signM2
                                // receive M4 = cid | hashAck | T6 | pubKeyCstr
                                String[] m4 = message.split("\\|");
                                System.out.println("Arrays.toString(m4) = " + Arrays.toString(m4));

                                long T6 = System.currentTimeMillis();
                                System.out.println("T6 = " + T6);

                                if (T6 - Long.parseLong(m4[2]) <= 5000) {
                                    String hashAck = Fungsi.hash(m4[0] + m4[3] + id);
                                    System.out.println("hashAck = " + hashAck);

                                    if (hashAck.equals(m4[1])) {
                                        System.out.println("**** VALID ****");

                                        String hashSignU_CA = Fungsi.hash(id + pubKeyUstr + m4[0] + m4[3]);
                                        System.out.println("hashSignU_CA = " + hashSignU_CA);

                                        //Convert StringBase64 to Public Key
                                        byte[] publicBytes = Base64.getDecoder().decode(m4[3]);
                                        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
                                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                                        PublicKey pubKeyS = keyFactory.generatePublic(keySpec);

                                        String signU_CA = Fungsi.encrypt(hashSignU_CA, pubKeyS);
                                        System.out.println("signU_CA = " + signU_CA);

                                        String userPublic_Cert = id + "|" + pubKeyUstr + "|" + m4[3] + "|" + m2[0] + "|" + signU_CA;
                                        System.out.println("userPublic_Cert = " + userPublic_Cert);

                                        // send userPublic_Cert = id | pubKeyUstr | pubKeyCstr | cloudID | signU_CA;
                                        out.println(userPublic_Cert);


                                        message = in.nextLine();
                                        String[] serverPublic_Cert = message.split("\\|");
                                        String hashSignS_CA = Fungsi.hash(serverPublic_Cert[0] + serverPublic_Cert[1] + id + pubKeyUstr);

                                        if (hashSignS_CA.equals(Fungsi.decrypt(serverPublic_Cert[4],privKeyU))) {
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
                            } else {
                                System.out.println("Wrong secret key!");
                                out.println(Fungsi.ERROR);
                            }

                        } else {
                            System.out.println("Wrong secret key!");
                            out.println(Fungsi.ERROR);
                        }
                    } else {
                        System.out.println("Error Timeout!");
                        out.println(Fungsi.ERROR);
                    }
                } else {
                    System.out.println("Wrong secret key!");
//                    out.println(Fungsi.ERROR);
                }
                System.out.print("\nCheck Secret Key : ");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
