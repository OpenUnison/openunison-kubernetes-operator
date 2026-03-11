package com.tremolosecurity.openunison.secret;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;

import java.io.InputStream;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.BiConsumer;

public class SecretWatcher {

    private static final Duration WATCH_TIMEOUT = Duration.ofMinutes(30);
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);

    
    private final ObjectMapper mapper = new ObjectMapper();

    // namespace -> set of secret names
    private final Map<String, Map<String,SecretToWatch>> watchedSecrets = new ConcurrentHashMap<>();

    // namespace -> current resourceVersion
    private final Map<String, String> resourceVersions = new ConcurrentHashMap<>();

    // namespace currently being watched
    private final Set<String> activeNamespaces = ConcurrentHashMap.newKeySet();

    private final ExecutorService executor = Executors.newCachedThreadPool();
    

    private volatile boolean running = true;

    private ClusterConnection cluster;
    private SecretVersionManager svm;

    public SecretWatcher(ClusterConnection cluster) throws Exception {
        this.cluster = cluster;
        this.svm = new SecretVersionManager(this.cluster);

        
    }

    /**
     * Add a single secret to watch. Namespace watcher is started if needed.
     */
    public void addSecret(String namespace, String secretName, String alias) {
        SecretToWatch secret = new SecretToWatch(secretName,alias);

        Map<String,SecretToWatch> nsWatches = watchedSecrets.get(namespace);

        if (nsWatches == null ) {
        
            // Start watcher only once per namespace
            if (activeNamespaces.add(namespace)) {
                executor.submit(() -> watchNamespace(namespace));
            }

            nsWatches = new HashMap<>();
            watchedSecrets.put(namespace,nsWatches);
        }

        

        nsWatches.put(secretName,secret);

        
    }

    /**
     * Main namespace watch loop with backoff.
     */
    private void watchNamespace(String namespace) {

        long backoffMillis = 1000;

        while (running) {
            try {

                // Initialize resourceVersion once
                if (!resourceVersions.containsKey(namespace)) {
                    String rv = fetchCurrentResourceVersion(namespace);
                    resourceVersions.put(namespace, rv);
                }

                watchLoop(namespace);
                backoffMillis = 1000; // reset backoff on success

            } catch (Exception e) {

                System.err.println("Watch error in namespace "
                        + namespace + ": " + e.getMessage());

                try {
                    Thread.sleep(backoffMillis);
                } catch (InterruptedException ignored) {}

                backoffMillis = Math.min(backoffMillis * 2, 30000);
            }
        }
    }

    /**
     * Opens the watch HTTP stream.
     */
    private void watchLoop(String namespace) throws Exception {

        String rv = resourceVersions.get(namespace);

        String uri = String.format(
                "%s/api/v1/namespaces/%s/secrets"
                        + "?watch=true"
                        + "&resourceVersion=%s"
                        + "&allowWatchBookmarks=true",
                cluster.getUrl(), namespace, rv);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .timeout(WATCH_TIMEOUT)
                .header("Authorization", "Bearer " + cluster.loadToken())
                .GET()
                .build();

        HttpResponse<InputStream> response =
                cluster.getHttp().send(request, HttpResponse.BodyHandlers.ofInputStream());

        if (response.statusCode() != 200) {
            throw new RuntimeException("Watch failed: HTTP "
                    + response.statusCode());
        }

        try (Scanner scanner = new Scanner(response.body())) {
            while (running && scanner.hasNextLine()) {
                processEvent(namespace, scanner.nextLine());
            }
        }
    }

    /**
     * Processes a single watch event.
     */
    private void processEvent(String namespace, String jsonLine) throws Exception {

        JsonNode root = mapper.readTree(jsonLine);
        String type = root.path("type").asText();

        switch (type) {

            case "BOOKMARK" -> {
                String rv = root.path("object")
                        .path("metadata")
                        .path("resourceVersion")
                        .asText();

                resourceVersions.put(namespace, rv);
            }

            case "ERROR" -> {
                JsonNode obj = root.path("object");
                int code = obj.path("code").asInt();

                if (code == 410) {
                    // resourceVersion expired
                    System.out.println("resourceVersion expired for "
                            + namespace + ", resetting");

                    String newRv = fetchCurrentResourceVersion(namespace);
                    resourceVersions.put(namespace, newRv);

                } else {
                    throw new RuntimeException("K8s watch error: " + obj);
                }
            }

            case "MODIFIED","ADDED" -> {
                JsonNode obj = root.path("object");

                String name = obj.path("metadata").path("name").asText();
                String newRv = obj.path("metadata")
                        .path("resourceVersion").asText();

                resourceVersions.put(namespace, newRv);

                
                Map<String,SecretToWatch> nsSecrets = watchedSecrets.get(namespace);
                if (nsSecrets != null) {
                    SecretToWatch secret = nsSecrets.get(name);
                    if (secret != null) {
                        this.onSecret(namespace,secret.getName(),secret.getAlias());
                    }
                }
                

                
                
                
                
            }

            case "DELETED" -> {
                JsonNode obj = root.path("object");
                String rv = obj.path("metadata")
                        .path("resourceVersion").asText();

                if (!rv.isEmpty()) {
                    resourceVersions.put(namespace, rv);
                }
            }

            default -> {
                // ignore unknown types
            }
        }
    }

    

    /**
     * Fetch initial resourceVersion to ignore existing state.
     */
    private String fetchCurrentResourceVersion(String namespace) throws Exception {

        String uri = String.format(
                "%s/api/v1/namespaces/%s/secrets",
                this.cluster.getUrl(), namespace);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .header("Authorization", "Bearer " + this.cluster.loadToken())
                .GET()
                .build();

        HttpResponse<String> response =
                cluster.getHttp().send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to list secrets: HTTP "
                    + response.statusCode());
        }

        JsonNode root = mapper.readTree(response.body());
        return root.path("metadata")
                .path("resourceVersion")
                .asText();
    }


    public void onSecret(String namespace, String name, String alias) {
        svm.onSecret(namespace,name,alias);
    }

    /**
     * Graceful shutdown.
     */
    public void shutdown() {
        running = false;
        executor.shutdownNow();
    }
}

class SecretToWatch {
    String name;
    String alias;

    public SecretToWatch(String name) {
        this.name = name;
    }

    public SecretToWatch(String name,String alias) {
        this.name = name;
        this.alias = alias;
    }

    public String getName() {
        return this.name;
    }

    public String getAlias() {
        return this.alias;
    }

    @Override
    public boolean equals(Object o) {
        SecretToWatch toCheck = (SecretToWatch) o;
        return toCheck.getName().equals(this.name);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }
}