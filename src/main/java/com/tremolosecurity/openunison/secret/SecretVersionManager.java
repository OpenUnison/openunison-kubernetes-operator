package com.tremolosecurity.openunison.secret;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;


import java.net.URI;
import java.net.http.*;


public class SecretVersionManager {

    
    private final ObjectMapper mapper = new ObjectMapper();
    private ClusterConnection cluster;

    public SecretVersionManager(ClusterConnection cluster) throws Exception {

        this.cluster = cluster;
    }

    public void onSecret(String namespace, String name, String alias) {

        System.out.println("********** namespace:" + namespace +
                " / name:" + name +
                " / alias:" + alias);

        try {

            JsonNode existing = getSecretVersion(namespace, name);

            if (existing == null) {
                createSecretVersion(namespace, name, alias);
            } else {
                incrementSecretVersion(namespace, name, existing);
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

    private void createSecretVersion(String namespace, String name, String alias) throws Exception {

        ObjectNode root = mapper.createObjectNode();

        root.put("apiVersion", "openunison.tremolo.io/v1");
        root.put("kind", "SecretVersion");

        ObjectNode metadata = root.putObject("metadata");
        metadata.put("name", name);
        metadata.put("namespace", namespace);

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
    }

    private void incrementSecretVersion(String namespace,
                                        String name,
                                        JsonNode existing) throws Exception {

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
    }
}