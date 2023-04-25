package com.tremolosecurity.openunison.util;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

public class NetUtils {
    /**
     * Determine your IP address
     * @return
     * @throws SocketException
     */
    public static String whatsMyIP() throws SocketException {
        Enumeration<NetworkInterface> enumer = NetworkInterface.getNetworkInterfaces();
        while (enumer.hasMoreElements()) {
            NetworkInterface ni = enumer.nextElement();
            Enumeration<InetAddress> enumeri = ni.getInetAddresses();
            while (enumeri.hasMoreElements()) {
                InetAddress addr = enumeri.nextElement();
                if (! addr.getHostAddress().startsWith("127")) {
                    return addr.getHostAddress();
                }
            }
        }

        return "";
    }
}
