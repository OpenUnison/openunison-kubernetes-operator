package com.tremolosecurity.openunison.obj;

import org.json.simple.JSONObject;

public class WsResponse {
    int result;
    public int getResult() {
        return result;
    }

    JSONObject body;

    public JSONObject getBody() {
        return body;
    }

    public WsResponse(int result,JSONObject body) {
        this.result = result;
        this.body = body;
    }
    
}
