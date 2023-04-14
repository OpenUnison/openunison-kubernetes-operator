package com.tremolosecurity.openunison.operator;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.HashSet;

import javax.net.ssl.SSLContext;

import org.joda.time.DateTime;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import com.fasterxml.jackson.core.JsonParser;
import com.tremolosecurity.openunison.JSON;
import com.tremolosecurity.openunison.crd.OpenUnison;
import com.tremolosecurity.openunison.deployment.Updater;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;
import com.tremolosecurity.openunison.obj.WsResponse;
import com.tremolosecurity.openunison.secret.Generator;

public class Operator {
    ClusterConnection cluster;
    String lastProcessedVersion;

    HashSet<String> processedResources;
    private boolean continueWatch;
    int timeoutSeconds;

    public Operator(ClusterConnection cluster,int timeoutSeconds) {
        this.cluster = cluster;
        this.processedResources = new HashSet<String>();
        this.timeoutSeconds = timeoutSeconds;
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
                        this.lastProcessedVersion = resourceVersion;
                        // do it
                        System.out.println("Processing " + resourceVersion);
                        this.processedResources.add(resourceVersion);
                        
                        com.tremolosecurity.openunison.crd.OpenUnison ou = JSON.getGson().fromJson(obj.toString(), OpenUnison.class);

                        if (this.hasObjectChanged(obj)) {
                            
                            boolean succeeded = false;
                            System.out.println("Resource " + resourceVersion + " changed, processing");
                            try {

                                this.processObject(ou, (String) metadata.get("name"));
                                succeeded = true;
                            } catch (Throwable t) {
                                System.out.println("Could not process request:");
                                t.printStackTrace();
                                succeeded = false;

                            }

                            patchStatus(obj, metadata, succeeded);
                        } else {
                            System.out.println("Resource " + resourceVersion + " has not changed, not processing");
                            

                        }
                    }
                }
            }
        }


    }



    public void runWatch() throws Exception {
        this.continueWatch = true;
        SSLContext sslCtx = cluster.generateSSLContext();

        while (continueWatch) {
            HttpClient http = HttpClient.newBuilder()
                            .sslContext(sslCtx)
                            .build();


            StringBuilder urlBuilder = new StringBuilder().append(cluster.getWatchUrl()).append("?watch=true&timeoutSeconds=").append(this.timeoutSeconds).append("&allowWatchBookmarks=true");
            if (this.lastProcessedVersion != null) {
                urlBuilder.append("&resourceVersion=").append(this.lastProcessedVersion);
            }

            String url = urlBuilder.toString();
            System.out.println("Watching " + url);

            HttpRequest get = HttpRequest.newBuilder()
                            .uri(new URI(url))
                            .GET()
                            .header("Authorization", String.format("Bearer %s", cluster.loadToken()))
                            .build();

            HttpResponse<InputStream> resp = http.send(get,BodyHandlers.ofInputStream());

            if (resp.statusCode() != 200) {
                throw new Exception("Could not run watch : " + resp.statusCode());
            } else {
                BufferedReader in = new BufferedReader(new InputStreamReader(resp.body()));
                String line = null;
                while ((line = in.readLine()) != null) {
                    JSONObject root = (JSONObject) new JSONParser().parse(line);
                    String type = (String) root.get("type");
                    JSONObject obj = (JSONObject) root.get("object");

                    String resourceVersion = null;
                    JSONObject metadata = (JSONObject) obj.get("metadata");
                    if (metadata != null) {
                        resourceVersion = (String) metadata.get("resourceVersion");
                    }

                    System.out.println("Type: " + type);
                    System.out.println("Resource Version: " + resourceVersion);
                    this.lastProcessedVersion = resourceVersion;

                    if (type.equalsIgnoreCase("MODIFIED") || type.equals("ADDED")) {

                        this.processedResources.add(resourceVersion);
                        
                        com.tremolosecurity.openunison.crd.OpenUnison ou = JSON.getGson().fromJson(obj.toString(), OpenUnison.class);

                        if (this.hasObjectChanged(obj)) {
                            boolean succeeded = false;
                            System.out.println("Resource " + resourceVersion + " changed, processing");
                            try {

                                this.processObject(ou, (String) metadata.get("name"));
                                succeeded = true;
                            } catch (Throwable t) {
                                System.out.println("Could not process request:");
                                t.printStackTrace();
                                succeeded = false;

                            }

                            patchStatus(obj, metadata, succeeded);




                        } else {
                            System.out.println("Resource " + resourceVersion + " has not changed, not processing");

                            

                        }
                    } else if (type.equalsIgnoreCase("DELETED")) {

                    } else if (type.equalsIgnoreCase("BOOKMARK")) {
                        // do nothing, we already have the resource version
                    } else if (type.equalsIgnoreCase("ERROR")) {
                        String msg = (String) obj.get("message");
                            int indexstart = msg.indexOf('(');
                            if (indexstart == -1) {
                                //i'm not really sure how to handle this
                                throw new Exception(String.format("Could not process watch %s",msg));
                            } else {
                                int indexend = msg.indexOf(')');
                                String newResourceId = msg.substring(indexstart+1,indexend);
                                this.lastProcessedVersion = newResourceId;
                                this.processedResources.add(newResourceId);
                            }
                    }

                }
            }
        }

        System.out.println("Watch ended");
    }

    private void patchStatus(JSONObject obj, JSONObject metadata, boolean succeeded)
            throws NoSuchAlgorithmException, UnsupportedEncodingException, org.json.simple.parser.ParseException,
            URISyntaxException, IOException, InterruptedException {
        JSONObject patch = new JSONObject();
        JSONObject status = new JSONObject();
        patch.put("status",status);
        status.put("digest",this.generateCheckSum(this.generateCleanCR(obj)));
        JSONObject conditions = new JSONObject();
        status.put("conditions",conditions);
        conditions.put("lastTransitionTime", DateTime.now().toString());
        if (succeeded) {
            conditions.put("status","True");
            conditions.put("type","Completed");
        } else {
            conditions.put("status","True");
            conditions.put("type","Failed");
        }

        System.out.println(patch.toJSONString());

        WsResponse res = cluster.patch(cluster.getUriPath() + "/" + metadata.get("name") + "/status", patch.toJSONString());
        if (res.getResult() == 200) {
            System.out.println("Resource patched");
        } else {
            System.out.println("Unable to patch : " + res.getResult() + " / " + res.getBody().toString());
        }
    }

    public void endWatch() {
        this.continueWatch = false;
    }

    private void processObject(com.tremolosecurity.openunison.crd.OpenUnison ou,String name) throws Exception {
        Generator gensecret = new Generator();
        boolean updateAmq = gensecret.load(ou,cluster,cluster.getNamespace(),name);
        new Updater(cluster,cluster.getNamespace(),name,updateAmq).rollout();

    }
    

    private boolean hasStatus(JSONObject object) {
        return object.get("status") != null;
    }

    private  boolean hasObjectChanged(JSONObject cr)
            throws ParseException, NoSuchAlgorithmException, UnsupportedEncodingException, org.json.simple.parser.ParseException {
        if (!hasStatus(cr)) {
            // no status, nothing to compare against so it has changed
            return true;
        }

        JSONObject chkObj = generateCleanCR(cr);

        String digestBase64 = generateCheckSum(chkObj);

        String existingDigest = (String) ((JSONObject) cr.get("status")).get("digest");
        return existingDigest == null || !existingDigest.equals(digestBase64);
    }

    private String generateCheckSum(JSONObject chkObj)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String jsonForChecksum = chkObj.toJSONString();
        MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        digest.update(jsonForChecksum.getBytes("UTF-8"), 0, jsonForChecksum.getBytes("UTF-8").length);
        byte[] digestBytes = digest.digest();
        String digestBase64 = java.util.Base64.getEncoder().encodeToString(digestBytes);
        return digestBase64;
    }

    private  JSONObject generateCleanCR(JSONObject cr) throws org.json.simple.parser.ParseException {
        JSONParser parser = new JSONParser();

        JSONObject chkObj = new JSONObject();
        chkObj.put("apiVersion", cr.get("apiVersion"));
        chkObj.put("kind", cr.get("kind"));
        chkObj.put("spec", cr.get("spec"));

        JSONObject metadata = (JSONObject) parser.parse(((JSONObject) cr.get("metadata")).toJSONString());

        metadata.remove("creationTimestamp");
        metadata.remove("generation");
        metadata.remove("resourceVersion");
        metadata.remove("managedFields");

        chkObj.put("metadata", metadata);
        return chkObj;
    }
}
