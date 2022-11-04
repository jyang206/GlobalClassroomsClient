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
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ClientMain {

	static int serverPort = 4030;
	public static void main(String[] args) {
		Scanner sc=new Scanner(System.in);
		System.out.println("Ingrese la cantidad de clientes que desea crear");
		int cant=sc.nextInt();
		for(int i=0;i<cant;i++) {
			ClientThrd client = new ClientThrd(i ,serverPort);
			client.start();
		}
	}
}