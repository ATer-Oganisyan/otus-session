import java.io.IOException;
import java.io.OutputStream;
import java.io.*;
import java.net.InetSocketAddress;
import java.util.*;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.sql.*;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.URI;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

public class SessionServer {

    private static HttpClient client = HttpClient.newBuilder().build();
    private static String host = "";

    private static Map<String, Map<String, String>> sessions = new HashMap<>();

    public static void main(String[] args) throws Exception {
        host = args[0];
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/", new MyHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
    }

    static class MyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange t) throws IOException {
            System.out.println("Request accepted");
            String path = t.getRequestURI().getPath();
            System.out.println("Path: " + path);
            if ("/health".equals(path)) {
                System.out.println("matched health");
                routeHealth(t);
            } else if ("/auth".equals(path)) {
                System.out.println("matched auth");
                routeAuth(t);
            } else if ("/unauth".equals(path)) {
                System.out.println("matched unauth");
                routeUnauth(t);
            } else if ("/session".equals(path)) {
                System.out.println("matched session");
                routeSession(t);
            } else {
                System.out.println("not matched");
                String response = "{\"status\": \"not found\"}";
                t.sendResponseHeaders(404, response.length());
                OutputStream os = t.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        }
    }

    /**
     * From ingress
     * @param t
     * @throws IOException
     */
    static private void routeHealth(HttpExchange t) throws IOException {
        System.out.println("Request accepted");
        String response = "{\"status\": \"OK\"}";
        t.sendResponseHeaders(200, response.length());
        OutputStream os = t.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    /**
     * From ingress
     * @param t
     * @throws IOException
     */
    static private void routeAuth(HttpExchange t) throws IOException {
        System.out.println("Route routeAuth");
        Map<String, String> request = postToMap(buf(t.getRequestBody()));
        Map<String, String> userInfo = getUserInfo(request.get("login"), request.get("pwd"));
        if (userInfo == null) {
            String r = "wrong credentials";
            OutputStream os = t.getResponseBody();
            t.sendResponseHeaders(403, r.length());
            os.write(r.getBytes());
            os.close();
            return;
        }
        String r = "role:user";
        sessions.put(userInfo.get("token"), userInfo);
        OutputStream os = t.getResponseBody();
        t.getResponseHeaders().add("cookie", "token=" + userInfo.get("token"));
        t.sendResponseHeaders(200, r.length());
        os.write(r.getBytes());
        os.close();
    }

    static private Map<String, String> getUserInfo(String login, String pwd) {
        String body = "login:" + login;
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(host + "/get-by-login"))
                .timeout(Duration.ofMinutes(1))
                .header("Content-Type", "plain/text")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response;
        try {
            response = client.send(request, BodyHandlers.ofString());
        } catch (IOException e) {
            System.out.println("IOException");
            throw new RuntimeException();
        } catch (InterruptedException e) {
            System.out.println("IOException");
            throw new RuntimeException();
        }

        if (response.statusCode() != 200) {
            return null;
        }
        String responsBody = response.body();
        Map<String, String> responseMap = postToMap(new StringBuilder(responsBody));
        String id = responseMap.get("id");
        String pwdEncrypted = responseMap.get("pwd_crypted");
        if (getMd5(pwd) != pwdEncrypted || pwdEncrypted == null || "".equals(pwdEncrypted)) {
            return null;
        }
        String token = getMd5(pwdEncrypted);
        HashMap<String, String> userInfo = new HashMap<>();
        userInfo.put("id", id);
        userInfo.put("token", token);
        return userInfo;
    }

    private static String getMd5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            String hashtext = no.toString(16);
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("NoSuchAlgorithmException");
            return null;
        }
    }

    /**
     * From profie service
     *
     * @param t
     * @throws IOException
     */
    static private void routeSession(HttpExchange t) throws IOException {
        System.out.println("Route routeSession");
        Map<String, String> request = postToMap(buf(t.getRequestBody()));
        Map<String, String> userInfo = sessions.get(request.get("token"));
        if (userInfo == null) {
            String r = "session does not exists";
            OutputStream os = t.getResponseBody();
            t.sendResponseHeaders(403, r.length());
            os.write(r.getBytes());
            os.close();
            return;
        }
        String r = "id:" + userInfo.get("id") + "\nrole:user";
        OutputStream os = t.getResponseBody();
        t.sendResponseHeaders(200, r.length());
        os.write(r.getBytes());
        os.close();
    }

    /**
     * From ingress
     * @param t
     * @throws IOException
     */
    static private void routeUnauth(HttpExchange t) throws IOException {
        System.out.println("Route routeUnauth");
        String cookieString = String.join(";", t.getResponseHeaders().get("cookie"));
        Map<String, String> cookie = postToMap(new StringBuilder(cookieString));
        String token = cookie.get("token");
        sessions.remove(token);
        String r = "";
        OutputStream os = t.getResponseBody();
        t.sendResponseHeaders(200, r.length());
        os.write(r.getBytes());
        os.close();
    }

    static private Map<String, String> queryToMap(String query) {
        if(query == null) {
            return new HashMap<>();
        }
        Map<String, String> result = new HashMap<>();
        for (String param : query.split("&")) {
            String[] entry = param.split("=");
            if (entry.length > 1) {
                result.put(entry[0], entry[1]);
            }else{
                result.put(entry[0], "");
            }
        }
        return result;
    }

    static private Map<String, String> postToMap(StringBuilder body){
        String[] parts = body
                .toString()
                .replaceAll("\r", "")
                .replaceAll("=", ":")
                .replaceAll(" ", "")
                .replaceAll(";", "\n")
                .split("\n");
        Map<String, String> result = new HashMap<>();
        for (String part: parts) {
            String[] keyVal = part.split(":");
            result.put(keyVal[0], keyVal[1]);
        }
        System.out.println("buf: " + result.toString());
        return result;
    }

    static private StringBuilder buf(InputStream inp)  throws UnsupportedEncodingException, IOException {
        InputStreamReader isr =  new InputStreamReader(inp,"utf-8");
        BufferedReader br = new BufferedReader(isr);
        int b;
        StringBuilder buf = new StringBuilder(512);
        while ((b = br.read()) != -1) {
            buf.append((char) b);
        }
        br.close();
        isr.close();
        System.out.println("buf : " + buf);
        return buf;
    }
}