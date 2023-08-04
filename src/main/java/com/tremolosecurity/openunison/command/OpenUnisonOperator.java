package com.tremolosecurity.openunison.command;

import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import com.tremolosecurity.openunison.certs.CheckCerts;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;
import com.tremolosecurity.openunison.operator.Operator;

public class OpenUnisonOperator {
    
    public static void main(String[] args) throws Exception {
        String command = args[0];
        String url = args[1];
        String namespace = args[2];
        String pathToToken = args[3];
        String pathToCertificate = args[4];
        String versions = args[5];
        String webhooks = "";

        List<String> mutationHooks = new ArrayList<String>();
        List<String> admmissionHooks = new ArrayList<String>();

        if (args.length == 7) {
            webhooks = args[6];
        }

        System.out.println("command: " + command);
        System.out.println("url: " + url);
        System.out.println("namespace: " + namespace);
        System.out.println("path to  token: " + pathToToken);
        System.out.println("path to certificate: " + pathToCertificate);
        System.out.println("versions: " + versions);
        System.out.println("webhooks to update: " + webhooks);
        

        if (webhooks.contains("/")) {
            String validators = webhooks.substring(0,webhooks.indexOf("/"));
            String mutators = webhooks.substring(webhooks.indexOf("/") + 1);

            StringTokenizer toker = new StringTokenizer(validators,",",false);
            while (toker.hasMoreTokens()) {
                admmissionHooks.add(toker.nextToken());
            }

            toker = new StringTokenizer(mutators,",",false);
            while (toker.hasMoreTokens()) {
                mutationHooks.add(toker.nextToken());
            }


        }


        ClusterConnection cluster = new ClusterConnection(url,namespace,pathToCertificate,pathToToken,versions.split(","));

        cluster.findVersion();

        if (command.equalsIgnoreCase("operator")) {
            Operator operator = new Operator(cluster,10,admmissionHooks,mutationHooks);
            operator.init();

            try {
                operator.runWatch();
            } catch (Throwable t) {
                System.out.println("Problem running watch, restarting");
                t.printStackTrace();
            }
        } else if (command.equalsIgnoreCase("check-certs")) {
            System.out.println("Checking certificats in namespace");
            CheckCerts checkCerts = new CheckCerts();
            checkCerts.checkCerts(cluster);
        }
        
    }
}
