package com.tremolosecurity.openunison.util;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.io.InputStream;

public class K8sResourceVersionParser {

    public static String parseListResourceVersion(InputStream json) throws Exception {
        JsonFactory factory = new JsonFactory();

        try (JsonParser parser = factory.createParser(json)) {
            String currentField = null;
            boolean insideTopMetadata = false;
            int metadataDepth = -1;

            while (parser.nextToken() != null) {
                JsonToken token = parser.currentToken();

                if (token == JsonToken.FIELD_NAME) {
                    currentField = parser.currentName();
                    System.out.println("##### fieldname: " + currentField);

                    if ("metadata".equals(currentField)) {
                        JsonToken next = parser.nextToken();

                        if (next == JsonToken.START_OBJECT) {
                            insideTopMetadata = true;
                            metadataDepth = parser.currentLocation().getCharOffset() >= 0 ? 1 : 1;
                        }
                    } else if (insideTopMetadata && "resourceVersion".equals(currentField)) {
                        parser.nextToken();
                        return parser.getValueAsString();
                    }
                } else if (insideTopMetadata && token == JsonToken.END_OBJECT) {
                    insideTopMetadata = false;
                }
            }
        }

        return null;
    }
}