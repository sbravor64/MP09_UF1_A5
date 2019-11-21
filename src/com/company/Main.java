package com.company;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;

public class Main {

    public static void main(String[] args) throws Exception {
        CodisClaus codisClaus = new CodisClaus();

        String text="hola nene";
        KeyPair key = codisClaus.randomGenerate(1024);
        byte[] datos = text.getBytes();

        //Ejercicio 1 - encriptar
        byte[] datosEncriptados=codisClaus.encryptData(datos,key.getPublic());

        //Ejercicio 1 - desencriptar
        byte[] datosDesencriptar= codisClaus.dencryptData(datosEncriptados, key.getPrivate());
        System.out.println(new String(datosDesencriptar));

        //Ejercicio 1.2.1 - keystore
        KeyStore ks = KeyStore.getInstance("PKCS12");
        String ksFile = "/home/dam2a/keystore_andresbravo.key";
        String ksPwd = "andres";

        File f = new File (ksFile);
        if (f.isFile()) {
            FileInputStream in = new FileInputStream(f);
            ks.load(in, ksPwd.toCharArray());

            System.out.println("----------------------------");
            System.out.println(ks.getType());
            System.out.println("----------------------------");
            System.out.println(ks.size());
            System.out.println("----------------------------");

            Enumeration<String> alias = ks.aliases();
            while (alias.hasMoreElements()) {
                String s = alias.nextElement();

                System.out.println(s);
                System.out.println(ks.getCertificate(s));

                System.out.println("----------------------------");
            }

            System.out.println(ks.getKey("mykey", ksPwd.toCharArray()).getAlgorithm());
        }

        //Ejercicio 1.2.2 - clau simetrica
        SecretKey sk = codisClaus.keygenKeyGeneration(128);
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(sk);
        KeyStore.PasswordProtection protectionParameter = new KeyStore.PasswordProtection(ksPwd.toCharArray());

        ks.setEntry("nuevo", secretKeyEntry, protectionParameter);

        ksFile="/home/dam2a/filenuevo.key";

        File f_nuevo = new File (ksFile);

        if (f_nuevo.isFile()) {
            FileOutputStream out = new FileOutputStream(f_nuevo);
            ks.store(out,ksPwd.toCharArray());
            out.close();
        }

        //Ejercicio 1.2.3 - certificado .cer
        PublicKey pub = codisClaus.getPublicKey("/home/dam2a/keystore_andresbravo.cer");
        System.out.println(pub);

        //Ejercicio 1.2.4
        FileInputStream is = new FileInputStream("/home/dam2a/keystore_andres_bravo.jks");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, ksPwd.toCharArray());

        String alias = "mykey";

        Key clau = keystore.getKey(alias, ksPwd.toCharArray());
        if (clau instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = keystore.getCertificate(alias);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();
            System.out.println(publicKey.toString());
        }

        //EJercicio 1.2.5
        byte[] dataBy = "data".getBytes();

        PrivateKey privKey = key.getPrivate();

        byte[] firma = codisClaus.signData(dataBy,privKey);

        System.out.println(new String(firma));


        //Ejercicio 1.2.6
        PublicKey publicKey = key.getPublic();

        boolean verificado = CodisClaus.validateSignature(dataBy,firma,publicKey);

        System.out.println(verificado);


        //Ejercicio 2
        System.out.println("\nEjercicio 2.2\n**********************\n");

        KeyPair claves = codisClaus.randomGenerate(1024);

        PublicKey pubKey = claves.getPublic();
        PrivateKey privateKey = claves.getPrivate();

        byte[][] clauEmbEnc = codisClaus.encryptWrappedData(dataBy,pubKey);


        byte[]  clauEmbDec = codisClaus.decryptWrappedData(clauEmbEnc,privateKey);

        System.out.println(new String(clauEmbDec));
    }
}
