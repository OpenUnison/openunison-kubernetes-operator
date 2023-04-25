package com.tremolosecurity.openunison.sql;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import com.tremolosecurity.openunison.crd.OpenUnison;
import com.tremolosecurity.openunison.kubernetes.ClusterConnection;
import com.tremolosecurity.openunison.secret.Generator;

public class RunSQL {
    
    public RunSQL() {

    }

    public void runSQL(OpenUnison ou,Generator secret) throws Exception {
        if (ou.getSpec().getSqlCheckQuery() == null || ou.getSpec().getSqlCheckQuery().isEmpty()) {
            throw new Exception("No SQL Check set");
        }
        
        String driver = secret.getProps().get("OU_JDBC_DRIVER");
        
        if (driver == null) {
            throw new Exception("jdbc driver is missing");
        }
        
        String url = secret.getProps().get("OU_JDBC_URL");

        if (url == null) {
            throw new Exception("jdbc url is missing");
        }


        String user = secret.getProps().get("OU_JDBC_USER");

        if (user == null) {
            System.out.println("WARN: jdbc user is missing");
        }

        String password = secret.getProps().get("OU_JDBC_PASSWORD");

        if (password == null) {
            System.out.println("WARN: jdbc password is missing");
        }

        Class.forName(driver);
        Connection con = null;
        
        if (url.toLowerCase().contains("authentication=activedirectoryintegrated") || url.toLowerCase().contains("authentication=activedirectorymsi") || url.toLowerCase().contains("integratedsecurity=true")) {
            // we're using AD, no username or password
            con = DriverManager.getConnection(url);
        } else {
            con = DriverManager.getConnection(url, user, password);


        }

        ResultSet res = con.createStatement().executeQuery(ou.getSpec().getSqlCheckQuery());

        if (res.next()) {
            System.out.println("Check query succeeded, skipping SQL");
            while (res.next());
        } else {
            System.out.println("Check query failed, running SQL");

            List<String> sqls = this.parseSQL(ou.getSpec().getRunSql());
            Statement stmt = con.createStatement();
            for (String sql : sqls) {
                System.out.println("SQL: '" + sql + "'");
                stmt.execute(sql);
            }

            stmt.close();

        }

        con.close();
 
 
    }

    

    /**
     * Parse a list of SQL statements from the source of a file
     * @param source
     * @return
     * @throws IOException
     */
    private List<String> parseSQL(String source) throws IOException {
        ArrayList<String> sqlStatements = new ArrayList<String>();

        BufferedReader in = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(source.getBytes("UTF-8"))));

        String line;
        String sql = null;

        while ((line = in.readLine()) != null) {
            if (sql == null) {
                if (line.trim().length() == 0 || line.trim().startsWith("#") || line.trim().startsWith("-")) {
                    continue;
                } else {
                    sql = line;
                }
            } else {
                sql += " " + line;

            }

            if (sql.trim().endsWith(";")) {
                sql = sql.trim();
                sql = sql.substring(0,sql.lastIndexOf(';'));
                sqlStatements.add(sql);
                sql = null;
            }
        }



        return sqlStatements;

    }
}
