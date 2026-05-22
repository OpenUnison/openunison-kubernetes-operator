package com.tremolosecurity.openunison.secret;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tremolosecurity.openunison.crd.OpenUnison;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;


import java.net.URI;
import java.net.http.*;
import java.security.SecureRandom;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class SecretVersionManager {

    
    private final ObjectMapper mapper = new ObjectMapper();
    private ClusterConnection cluster;

    public SecretVersionManager(ClusterConnection cluster) throws Exception {

        this.cluster = cluster;
    }

    public void onSecret(String namespace, String name, String alias,String updateUrl,OpenUnison ou) {

        System.out.println("********** namespace:" + namespace +
                " / name:" + name +
                " / alias:" + alias);

        try {

            JsonNode existing = getSecretVersion(namespace, name);

            if (existing == null) {
                createSecretVersion(namespace, name, alias,updateUrl,ou);
            } else {
                incrementSecretVersion(namespace, name, existing,updateUrl,ou);
            }

        } catch (Exception e) {
            throw new RuntimeException("Failed processing SecretVersion", e);
        }
    }

    private JsonNode getSecretVersion(String namespace, String name) throws Exception {

        String uri = String.format(
                "%s/apis/openunison.tremolo.io/v1/namespaces/%s/secretversions/%s",
                cluster.getUrl(), namespace, name);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .header("Authorization", "Bearer " + cluster.loadToken())
                .GET()
                .build();

        HttpResponse<String> response =
                cluster.getHttp().send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 404) {
            return null;
        }

        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to get SecretVersion: "
                    + response.statusCode() + " " + response.body());
        }

        return mapper.readTree(response.body());
    }

    private static HttpClient createInsecureClient() throws Exception {

        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }
        };

        SSLContext sslContext = SSLContext.getInstance("TLS");

        sslContext.init(null, trustAllCerts, new SecureRandom());

        SSLParameters sslParams = new SSLParameters();

        // Disable hostname verification
        sslParams.setEndpointIdentificationAlgorithm("");

        return HttpClient.newBuilder()
                .sslContext(sslContext)
                .sslParameters(sslParams)
                .build();
    }

    private void createSecretVersion(String namespace, String name, String alias, String updateUrl,OpenUnison ou) throws Exception {

        ObjectNode root = mapper.createObjectNode();

        root.put("apiVersion", "openunison.tremolo.io/v1");
        root.put("kind", "SecretVersion");

        ObjectNode metadata = root.putObject("metadata");
        metadata.put("name", name);
        metadata.put("namespace", namespace);

        ArrayNode ownerRefs = mapper.createArrayNode();
        ObjectNode ownerRef = mapper.createObjectNode();
        ownerRefs.add(ownerRef);
        metadata.set("ownerReferences",ownerRefs);
        ownerRef.put("apiVersion",ou.getApiVersion());
        ownerRef.put("kind","OpenUnison");
        ownerRef.put("name",ou.getMetadata().getName());
        ownerRef.put("uid",ou.getMetadata().getUid());
        ownerRef.put("controller",true);



        ObjectNode spec = root.putObject("spec");
        spec.put("key_name", alias);
        spec.put("version", 2);



        String uri = String.format(
                "%s/apis/openunison.tremolo.io/v1/namespaces/%s/secretversions",
                cluster.getUrl(), namespace);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .header("Authorization", "Bearer " + cluster.loadToken())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(root.toString()))
                .build();

        HttpResponse<String> response =
                cluster.getHttp().send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 201) {
            throw new RuntimeException("Failed to create SecretVersion: "
                    + response.statusCode() + " " + response.body());
        }

        System.out.println("Created SecretVersion " + namespace + "/" + name);

        if (updateUrl != null && ! updateUrl.isBlank()) {
          ObjectNode toUpdate = mapper.createObjectNode();
          toUpdate.put("key_name","alias");
          toUpdate.put("version",2);

          HttpClient updateClient = createInsecureClient();

          request = HttpRequest.newBuilder()
                .uri(URI.create(updateUrl))
                .header("Authorization", "Bearer " + cluster.loadToken())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(toUpdate.toString()))
                .build();

          response =
                updateClient.send(request, HttpResponse.BodyHandlers.ofString());

          if (response.statusCode() != 200) {
            System.out.println("WARNING: could not update to " + updateUrl + " " + response.body());
          }

          updateClient.close();
        }
    }

    private void incrementSecretVersion(String namespace,
                                        String name,
                                        JsonNode existing, String updateUrl,OpenUnison ou) throws Exception {

        int currentVersion = existing
                .path("spec")
                .path("version")
                .asInt();

        String resourceVersion = existing
                .path("metadata")
                .path("resourceVersion")
                .asText();

        int newVersion = currentVersion + 1;

        ObjectNode updated = (ObjectNode) existing.deepCopy();
        ((ObjectNode) updated.path("metadata"))
        .put("resourceVersion", resourceVersion);

        ((ObjectNode) updated.path("spec"))
                .put("version", newVersion);

        ObjectNode metadata = (ObjectNode) updated.get("metadata");
        ArrayNode ownerRefs = mapper.createArrayNode();
        ObjectNode ownerRef = mapper.createObjectNode();
        ownerRefs.add(ownerRef);
        metadata.set("ownerReferences",ownerRefs);
        ownerRef.put("apiVersion",ou.getApiVersion());
        ownerRef.put("kind","OpenUnison");
        ownerRef.put("name",ou.getMetadata().getName());
        ownerRef.put("uid",ou.getMetadata().getUid());
        ownerRef.put("controller",true);

        String uri = String.format(
                "%s/apis/openunison.tremolo.io/v1/namespaces/%s/secretversions/%s",
                cluster.getUrl(), namespace, name);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .header("Authorization", "Bearer " + cluster.loadToken())
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(updated.toString()))
                .build();

        HttpResponse<String> response =
                cluster.getHttp().send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to update SecretVersion: "
                    + response.statusCode() + " " + response.body());
        }

        System.out.println("Incremented SecretVersion "
                + namespace + "/" + name
                + " to version " + newVersion);

        if (updateUrl != null && ! updateUrl.isBlank()) {
          ObjectNode toUpdate = mapper.createObjectNode();
          toUpdate.put("key_name","alias");
          toUpdate.put("version",newVersion);

          HttpClient updateClient = createInsecureClient();

          request = HttpRequest.newBuilder()
                .uri(URI.create(updateUrl))
                .header("Authorization", "Bearer " + cluster.loadToken())
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(toUpdate.toString()))
                .build();

          response =
                updateClient.send(request, HttpResponse.BodyHandlers.ofString());

          if (response.statusCode() != 200) {
            System.out.println("WARNING: could not update to " + updateUrl + " " + response.body());
          }

          updateClient.close();
        }
    }
}