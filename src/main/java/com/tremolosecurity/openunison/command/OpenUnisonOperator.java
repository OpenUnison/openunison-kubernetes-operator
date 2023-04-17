package com.tremolosecurity.openunison.command;

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

        System.out.println("command: " + command);
        System.out.println("url: " + url);
        System.out.println("namespace: " + namespace);
        System.out.println("path to  token: " + pathToToken);
        System.out.println("path to certificate: " + pathToCertificate);
        System.out.println("versions: " + versions);
        
        ClusterConnection cluster = new ClusterConnection(url,namespace,pathToCertificate,pathToToken,versions.split(","));

        cluster.findVersion();

        if (command.equalsIgnoreCase("operator")) {
            Operator operator = new Operator(cluster,10);
            operator.init();

            try {
                operator.runWatch();
            } catch (Throwable t) {
                System.out.println("Problem running watch, restarting");
                t.printStackTrace();
            }
        }
        
    }
}
