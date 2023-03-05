package com.tremolosecurity.openunison.operator;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.HashSet;

import javax.net.ssl.SSLContext;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.tremolosecurity.openunison.JSON;
import com.tremolosecurity.openunison.crd.OpenUnison;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;

public class Operator {
    ClusterConnection cluster;

    HashSet<String> processedResources;

    public Operator(ClusterConnection cluster) {
        this.cluster = cluster;
        this.processedResources = new HashSet<String>();
    }

    public void init() throws Exception {
        JSON.setGson(JSON.createGson().create());
        SSLContext sslCtx = cluster.generateSSLContext();
        HttpClient http = HttpClient.newBuilder()
                            .sslContext(sslCtx)
                            .build();

        HttpRequest get = HttpRequest.newBuilder()
                            .uri(new URI(cluster.getWatchUrl()))
                            .GET()
                            .header("Authorization", String.format("Bearer %s", cluster.loadToken()))
                            .build();

        HttpResponse<String> resp = http.send(get,BodyHandlers.ofString());

        if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
            System.err.println("Could not load " + cluster.getWatchUrl() +" - " + resp.statusCode() + " / " + resp.body());
            System.exit(1);
        } else {
            String json = resp.body();
            System.out.println("Processing " + json);
            
            JSONObject root = (JSONObject) new JSONParser().parse(json);
            JSONArray items = (JSONArray) root.get("items");
            for (Object o : items) {
                JSONObject obj = (JSONObject) o;
                JSONObject metadata = (JSONObject) obj.get("metadata");
                String resourceVersion = (String) metadata.get("resourceVersion");
                if (resourceVersion != null) {
                    if (this.processedResources.contains(resourceVersion)) {
                        System.out.println("Version " + resourceVersion + " already processed, skipping");
                    } else {

                        // do it
                        System.out.println("Processing " + resourceVersion);
                        this.processedResources.add(resourceVersion);
                        obj.remove("metadata");
                        obj.remove("kind");
                        obj.remove("apiVersion");
                        com.tremolosecurity.openunison.crd.OpenUnison ou = JSON.getGson().fromJson(obj.toString(), OpenUnison.class);

                        System.out.println(ou.getSpec().getImage());
                    }
                }
            }
        }


    }
}
