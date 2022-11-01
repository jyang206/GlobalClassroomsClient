package dhclient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketImpl;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ClientThrd extends Thread{
    
    private Socket socket;
    private ClientUtil util;
    private SecurityFunctions f;
    private String clnt;
    private int serverPort;
    private InetAddress host;


    public ClientThrd(Socket socket, int clntid, int serverPort) {
        this.socket = socket;
        this.clnt = clnt;
        util = new ClientUtil();
        f = new SecurityFunctions();
    }

    private static BigInteger G2Y(BigInteger base, BigInteger exponente, BigInteger modulo) {
      // la base es el g
      return base.modPow(exponente,modulo);
    }
  
    private static BigInteger calcular_llave_maestra(BigInteger base, BigInteger exponente, BigInteger modulo) {
      //la base es el y del otro / el exponente es el x propio / el modulo es el p compartido 
      return base.modPow(exponente, modulo);
    }

    private byte[] generateIvBytes() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return iv;
	  }
  
    public void run() {
      try{
      PublicKey publicKey = f.read_kplus("src/dhclient/datos_asim_srv.pub","0");

      InetAddress host = InetAddress.getLocalHost();
      
      try {
        socket = new Socket(host.getHostName(),serverPort);
      } catch (Exception e) {
        System.out.println("Failed to connect to server");
        e.printStackTrace();
      }

      PrintWriter socket_out = 
        new PrintWriter(socket.getOutputStream(),true);

      BufferedReader socket_in = new BufferedReader(
        new InputStreamReader(socket.getInputStream())
      );
      
      //Initiate connection
      socket_out.println("SECURE INIT");

      //Read in g,p,g2x,and signature
      String g = socket_in.readLine();
      String p = socket_in.readLine();
      String g2x = socket_in.readLine();
      String sig = socket_in.readLine();

      //Message that was used for signing
      String msg = g+","+p+","+g2x;

      System.out.println("g: " + g);
      System.out.println("P: " + p);
      System.out.println("g2x: " + g2x);
      System.out.println("sig: " + sig);

      byte[] sig_bytearr = util.str2byte(sig);

      //Part 1: Verify Signature
      try {
        if(f.checkSignature(publicKey, sig_bytearr, msg)) {
          socket_out.println("OK");
        } else {
          socket_out.println("ERROR");
        }
      } catch (Exception e) {
        e.printStackTrace();
      }
      //Part 2: Calculate g2y and send to server
      
      int idCl = 1;
      SecureRandom r = new SecureRandom();
      int x = Math.abs(r.nextInt());
      String clnt = new String("client #" + idCl + ": ");
      Long longx = Long.valueOf(x);
      BigInteger bix = BigInteger.valueOf(longx);// propio del cliente
      BigInteger g2y = G2Y(new BigInteger(g),bix, new BigInteger(p));
      String str_valor_comun = g2y.toString();
      System.out.println(clnt + "G2X: "+str_valor_comun);
      socket_out.println(str_valor_comun);

      //Part 3: Diffie Hellman Master Key calculation
      BigInteger DH_master_key = calcular_llave_maestra(new BigInteger(g2x),bix, new BigInteger(p));
      String str_llave = DH_master_key.toString();
      // generating symmetric key
			//llave del servidor para cifrar (simetrica)
			SecretKey sk_clnt = f.csk1(str_llave);
			//llave del HMAC para cifrar (simetrica)
			SecretKey sk_macClntKey = f.csk2(str_llave);
      //Generate iv1
      byte[] iv1 = generateIvBytes();
      String iv1_str = util.byte2str(iv1);
      IvParameterSpec iv1_spec = new IvParameterSpec(iv1);
      
      //send number to server cifered
      // generate random int
      int num = Math.abs(r.nextInt());
      String num_str = String.valueOf(num);
      byte[] num_bytearr = num_str.getBytes();
      // cifer the int
      byte[] num_cif = f.senc(num_bytearr, sk_clnt, iv1_spec, "Cliente");
      // send the int
      socket_out.println(util.byte2str(num_cif));
      // send hmac
      byte[] hmac = f.hmac(num_bytearr, sk_macClntKey);
      socket_out.println(util.byte2str(hmac));

      // send iv1
      socket_out.println(iv1_str);

      //Waits until the server sends "OK" / "ERROR"

      String ans_serv = socket_in.readLine();

      if(ans_serv.equals("OK")) {
        System.out.println("Server OK");
        
        //recieve Ans, HMAC, iv2
        String encrypted_ans = socket_in.readLine();
        String hmac_ans = socket_in.readLine();
        String iv2_str = socket_in.readLine();
        byte[] ans_bytearr = util.str2byte(encrypted_ans);
        byte[] hmac_ans_bytearr = util.str2byte(hmac_ans);
        byte[] iv2_bytearr = util.str2byte(iv2_str);  

        //decrypt ans and verify hmac
        IvParameterSpec iv2_spec = new IvParameterSpec(iv2_bytearr);
        byte[] ans_decif = f.sdec(ans_bytearr, sk_clnt, iv2_spec);
        boolean verificar_rta = f.checkInt(ans_decif, sk_macClntKey, hmac_ans_bytearr);
        //validar verificacion y enviar rta

      }
      else {
        System.out.println("Error en la comunicacion con el servidor");
        return;
      }


      socket.close();
      socket_out.close();
      socket_in.close();
    }
    catch (Exception e) {
      e.printStackTrace();
    }
  }
}
