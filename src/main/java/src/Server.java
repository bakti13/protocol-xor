package src;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;
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

//            Fungsi f = new Fungsi();

            try {
                Scanner in = new Scanner(socket.getInputStream());
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
//
                while (in.hasNextLine()) {
                    int cid = new Random().nextInt(100-10) + 10;
                    System.out.println("cid = " + cid);

                    String message = in.nextLine();

                    // id | H | T1 | signM1
                    System.out.println("message = " + message);
                    String[] m1 = message.split("\\|");
                    System.out.println("Arrays.toString(m1) = " + Arrays.toString(m1));


                    long T2 = System.currentTimeMillis();
                    System.out.println("T2 = " + T2);

                    // check if time <= 5 detik
                    if ( T2 - Long.parseLong(m1[2]) <= 5000) {

                        System.out.println("**** VALID ****");

                        String Hid = Fungsi.encryptThisString(String.valueOf(m1[0]));
                        System.out.println("Hid = " + Hid);
//
                        String Hpw = Fungsi.encryptThisString(SECRET_KEY);
                        System.out.println("Hpw = " + Hpw);

                        // H(HID|HPW|User-Rand-ID|T1)
                        String HC = Fungsi.encryptThisString(Hid + Hpw + m1[0]+ m1[2]);
                        System.out.println("HC = " + HC);

                        String N1 = Fungsi.xor(HC,m1[1]);
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

                            String N2 = Fungsi.xor(H,H);
                            System.out.println("N2 = " + N2);

                            // H(CID|HPW|N1|N2|T1|T2)
                            String simKey = Fungsi.encryptThisString(cid + Hpw + N1 + N2 + m1[2] + T3);
                            System.out.println("simKey = " + simKey);

                            String signM2 = Fungsi.encryptThisString(cid + H + N2 + T3);
                            System.out.println("signM2 = " + signM2);

                            // cid | H | T2 | signM2
                            String M2 = cid + "|" + H + "|" + T3 +"|"+ signM2;
                            System.out.println("M1 = " + M2);

                            System.out.println("Sennding to Client "+M2);
                            out.println(M2);


                            message = in.nextLine();
                            if (message.equals(Fungsi.ERROR)) {
                                System.out.println("**** NOT VALID ****");
                            } else if(message.equals(Fungsi.VALID)) {
                                System.out.println("**** SECRET KEY VALID ****");
                            }

                        } else {
                            System.out.println("**** NOT VALID ****");
                            System.out.println("Sennding to Client "+Fungsi.ERROR);
                            out.println(Fungsi.ERROR);
                        }
                    } else {
                        System.out.println("**** NOT VALID ****");
                        System.out.println("Sennding to Client "+Fungsi.ERROR);
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