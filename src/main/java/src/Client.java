package src;

import java.io.PrintWriter;
import java.net.Socket;
import java.util.Arrays;
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

                int id = new Random().nextInt(100-10) + 10;
                System.out.println("id = " + id);

                String Hid = Fungsi.encryptThisString(String.valueOf(id));
                System.out.println("Hid = " + Hid);

                String Hpw = Fungsi.encryptThisString(clientSecretKey);
                System.out.println("Hpw = " + Hpw);

                long T1 = System.currentTimeMillis();
                System.out.println("T1 = " + T1);

                String H = Fungsi.encryptThisString(Hid+Hpw+id+ T1);
                System.out.println("H = " + H);

                String N1 = Fungsi.xor(H,H);
                System.out.println("N1 = " + N1);

                String signM1 = Fungsi.encryptThisString(id + H + N1 + T1);
                System.out.println("signM1 = " + signM1);

                // id | H | T1 | signM1
                String M1 = id+"|"+H+"|"+T1+"|"+signM1;
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
                        String N2 = Fungsi.xor(HU,m2[1]);
                        System.out.println("N2 = " + N2);

                        // H[CID, H(CID|HID|HPW|User-Rand-ID|T1|T3),N2,T3]
                        String HM2 = Fungsi.encryptThisString(m2[0] + HU + N2 + m2[2]);
                        System.out.println("HM2 = " + HM2);

                        if (HM2.equals(m2[3])) {
                            System.out.println("**** VALID ****");

                            long T5 = System.currentTimeMillis();
                            System.out.println("T5 = " + T5);

                            // H(CID|HPW|N1|N2|T1|T3)
                            String simKey = Fungsi.encryptThisString(m2[0] + Hpw + N1 + N2 + T1 + m2[2]);
                            System.out.println("simKey = " + simKey);


                            // belum tau mau harus ngapain,
                            // di posisi ini secret key valid
                            System.out.println();
                            System.out.println("SECRET KEY VALID");
                            out.println(Fungsi.VALID);

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



//                System.out.println(System.currentTimeMillis());
//                Fungsi.delay(1000);
//                System.out.println(System.currentTimeMillis());
//                Fungsi.delay(5000);
//                System.out.println(System.currentTimeMillis());
//                Fungsi.delay(10000);
//                System.out.println(System.currentTimeMillis());

//                Exchange exchange = new Exchange();


//                /** Step 1.a: Bob/Client sends g^{x3}, g^{x4}
//                 **/
//                BigInteger x3 = new BigInteger(160, new SecureRandom());
//                x4 = new BigInteger(160, new SecureRandom());
//                HashMap<String, Object> mapClient = exchange.roundOne(x3, x4, CLIENTID);
//                /*Generate gx3, gx4, ZKP3, ZKP4 Bob/Client */
//                gx3 = new BigInteger((String) mapClient.get("gx3"));
//                System.out.println("x4 : " + x4);
//                System.out.println("gx3 : " + gx3);
//
//                /*Sending gx3, gx4, ZKP3, ZKP4 Bob/Client to Alice/Server*/
//                out.println(exchange.toJson(mapClient));
//
//                System.out.println();
//                System.out.println("**************************Step 1****************************");
//                System.out.println("Bob/Client sends to Alice/Server : ");
//                System.out.println("g^{x3} = " + mapClient.get("gx3"));
//                System.out.println("g^{x4} = " + mapClient.get("gx4"));
//                System.out.println("KP{x3} = " + exchange.toJson(mapClient.get("ZKP3")));
//                System.out.println("KP{x4} = " + exchange.toJson(mapClient.get("ZKP4")));
//
//                /** Step 1.b Bob/Client Verifies ZKP from Alice/Server
//                 **/
//                String message = in.nextLine();
//                // Mapping g^{x2}, KP{x1}, KP{x2} Alice/Server from response message
//                HashMap<String, Object> mapFromServer = exchange.fromJson(message);
//                gx1 = new BigInteger((String) mapFromServer.get("gx1"));
//                gx2 = new BigInteger((String) mapFromServer.get("gx2"));
//                sigX1 = exchange.toArray(mapFromServer.get("ZKP1"));
//                sigX2 = exchange.toArray(mapFromServer.get("ZKP2"));
//
//                // Bob/Client verifies Alice/Server ZKPs and also check g^{x2} != 1
//                boolean validZKPs = exchange.cekZKP(gx1, gx2, sigX1, sigX2, CLIENTID);
//
//                if (!validZKPs) {
//                    System.out.println("g^{x2} shouldn't be 1 or invalid KP{x1,x2}");
//                } else {
//                    System.out.println("Bob/Client checks g^{x2}!=1 = OK");
//                    System.out.println("Bob/Client checks KP{x1}    = OK");
//                    System.out.println("Bob/Client checks KP{x2}    = OK");
//                    System.out.println();
//
//                    /* Step 2.a : Bob/Client sending B*/
//                    s2 = exchange.getSecretBigInt(clientSecretKey);
//                    mapClient = exchange.roundTwo(gx3, gx1, gx2, x4, s2, CLIENTID);
//
//                    /* Generate B, gB, KP{x4*s} Bob/Client
//                     B = (BigInteger) mapClient.get("B");
//                     gB = (BigInteger) mapClient.get("gB");
//                     sigX4s = (BigInteger[]) mapClient.get("KP{x4*s}");*/
//
//                    // Sending B, gB, KP{x4*s} Bob/Client to Alice/Server
//                    out.println(exchange.toJson(mapClient));
//
//                    System.out.println("**************************Step 2****************************");
//                    System.out.println("Bob/Client sends to Alice/Server");
//                    System.out.println("B        = " + mapClient.get("B"));
//                    System.out.println("KP{x4*s} = " + exchange.toJson(mapClient.get("KP{x4*s}")));
//
//
//                    /** Step 2.b Bob/Client checks KP{x2*s} from Alice/Server
//                     **/
//                    message = in.nextLine();
//                    // Mapping A, gA, KP{x2*s} Alice/Server from response message
//                    mapFromServer = exchange.fromJson(message);
//                    A = new BigInteger((String) mapFromServer.get("A"));
//                    gA = new BigInteger((String) mapFromServer.get("gA"));
//                    sigX2s = exchange.toArray(mapFromServer.get("KP{x2*s}"));
//
//                    // Bob/Client verifies Alice/Server ZKPs
//                    validZKPs = exchange.chekZKPs(gA, A, sigX2s, CLIENTID);
//                    if (validZKPs) {
//                        System.out.println("Bob/Client checks KP{x2*s}: OK");
//
//                        /** Final Step: Generate Session Key (K) Bob/Client and sending to Alice/Server **/
//                        BigInteger key = exchange.getSessionKeys(gx2, x4, A, s2);
//
//                        // get key from Alice/Server
//                        message = in.nextLine();
//
//                        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
//
//                        // sending key to Alice/Server
//                        out.println(key.toString() + ";" + timestamp);
//
//                        System.out.println("\n***********************Final Steps**************************");
//                        System.out.println("Alice/Server computes a session key \t K=" + message);
//                        System.out.println("Bob/Client computes a session key \t\t K=" + key.toString() + ";" + timestamp);
//                        if (exchange.validateKey((message.split(";"))[0], key.toString())) {
//                            System.out.println("Secret key is VALID");
//                        } else {
//                            System.out.println("Secret key is NOT VALID");
//                        }
//                        System.out.println("************************************************************");
//                    } else {
//                        System.out.println("Invalid ZK{x2*s}");
//                    }
//                }
                System.out.print("\nCheck Secret Key : ");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
