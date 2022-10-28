package dhclient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.net.InetAddress;

import java.security.PublicKey;

public class ClientMain {
	static int serverPort = 4030;
	static private Socket socket;
	static private ClientUtil util;
	static private SecurityFunctions f;
	public static void main(String [] args) throws IOException, UnknownHostException {
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

		socket.close();
		socket_out.close();
		socket_in.close();
	}	
}
