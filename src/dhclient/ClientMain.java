package dhclient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
import java.net.InetAddress;

import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ClientMain {
	static int serverPort = 4030;
	static private Socket socket;
	static private ClientUtil util;
	static private SecurityFunctions f;
	public static void main(String [] args) throws Exception {
		util = new ClientUtil();
		f = new SecurityFunctions();
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

		//Compute G^y
		SecureRandom r=new SecureRandom();
		int y = Math.abs(r.nextInt());
		Long longy=Long.valueOf(y);
		BigInteger bigy=BigInteger.valueOf(longy);
		
		BigInteger big_g=new BigInteger(g);
		BigInteger big_p=new BigInteger(p);

		BigInteger g2y=G2Y(big_g,bigy,big_p);
		String str_valor_comun=g2y.toString();

		//Message to socket
		System.out.println("G^y: " + str_valor_comun);
		socket_out.println(str_valor_comun);

		//Compute G^(xy)
		BigInteger bigg2x=new BigInteger(g2x);
		BigInteger llave_maestra=calcularLlaveMaestra(bigg2x, bigy, big_p);
		//Generate Symmetric Keys
		String str_llave_maestra=llave_maestra.toString();
		System.out.println("Llave maestra: " + str_llave_maestra);
		
		SecretKey sk_clnt=f.csk1(str_llave_maestra);
		SecretKey sk_mac_clnt=f.csk2(str_llave_maestra);
		//Generate IV1

		byte[] iv1=generateIvBytes();
		String str_iv1=util.byte2str(iv1);
		IvParameterSpec ivSpec1=new IvParameterSpec(iv1);

		int consulta=10;

		//Encrypt and MAC
		String str_consulta=String.valueOf(consulta);
		byte[] byte_consulta=util.str2byte(str_consulta);

		byte[] encoded=f.senc(byte_consulta, sk_clnt, ivSpec1, "Cliente");

		byte[] encoded_mac=f.hmac(byte_consulta, sk_mac_clnt);

		socket_out.println(util.byte2str(encoded));
		socket_out.println(util.byte2str(encoded_mac));
		socket_out.println(str_iv1);

		//Read in response
		String respuesta=socket_in.readLine();
		if (respuesta.equals("OK")) {
			System.out.println("Sirve " );
		} else {
			System.out.println("No sirve" );
		}



		socket.close();
		socket_out.close();
		socket_in.close();
	}
	private static BigInteger G2Y(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente,modulo);
	}
	private static BigInteger calcularLlaveMaestra(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente,modulo);
	}
	private static byte[] generateIvBytes() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return iv;
	}
	
}