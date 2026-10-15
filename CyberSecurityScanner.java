import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CyberSecurityScanner {
    private static final String[] TOOLS = {"URL Security Scanner", "Password Strength Checker", "Email / Phishing Analyzer", "IP Address Analyzer", "File Hash / Integrity Checker", "Hash Generator", "Encryption / Decryption", "QR / Link Safety Analyzer", "Security Headers Checker", "Security Risk Assessment", "Phishing Awareness Test", "Login Security Tester"};
    private static final String[] ICONS = {"◎", "⌑", "✉", "⌘", "▤", "#", "▣", "▧", "⌁", "◇", "♧", "▣"};
    private static final String CSS = """
        :root{--bg:#080d19;--panel:#101827;--panel2:#131e30;--line:#202d40;--text:#edf3fb;--muted:#8594aa;--green:#38e5a1;--cyan:#59c7ef;--red:#ff7185;--amber:#f8c66b}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 53% -20%,#183552 0,transparent 44%),var(--bg);color:var(--text);font:15px Inter,Segoe UI,Arial,sans-serif;min-height:100vh}a{color:inherit;text-decoration:none}.layout{display:grid;grid-template-columns:248px 1fr;min-height:100vh}.side{padding:25px 17px;border-right:1px solid var(--line);background:#0a101ddc}.brand{display:flex;gap:12px;align-items:center;padding:0 10px 28px;font-weight:750;font-size:16px}.brandmark{width:38px;height:38px;border-radius:12px;background:linear-gradient(145deg,#47edaa,#20ab90);display:grid;place-items:center;color:#07241c;font-size:22px}.brand small{display:block;color:var(--muted);font-size:11px;font-weight:500;margin-top:4px;letter-spacing:.08em}.navlabel{font-size:10px;color:#65738a;font-weight:700;letter-spacing:.16em;padding:10px}.nav{display:grid;gap:4px}.nav a{color:#9aa8bc;padding:10px;border-radius:9px;font-size:12px;display:flex;align-items:center;gap:10px}.nav a:hover,.nav a.active{color:#ddfff3;background:#15322f}.nav a.active{box-shadow:inset 2px 0 var(--green)}.navicon{width:18px;color:var(--green);font-size:15px;text-align:center}.privacy{margin:28px 5px 0;padding:13px;border:1px solid var(--line);border-radius:10px;background:#0e1725;color:var(--muted);font-size:11px;line-height:1.6}.privacy strong{color:var(--green);display:block;margin-bottom:4px}.main{padding:24px clamp(18px,4vw,58px) 50px;max-width:1440px;width:100%;margin:auto}.top{height:44px;display:flex;justify-content:space-between;align-items:center;color:var(--muted);font-size:12px}.live{display:flex;align-items:center;gap:8px}.dot{width:7px;height:7px;background:var(--green);border-radius:50%;box-shadow:0 0 10px var(--green)}.hero{padding:43px 0 30px;max-width:850px}.eyebrow{color:var(--green);text-transform:uppercase;letter-spacing:.18em;font-size:10px;font-weight:750}.hero h1{font-size:clamp(37px,5vw,65px);line-height:1.05;letter-spacing:-.055em;margin:17px 0}.hero h1 span{color:var(--green)}.hero p{color:#9aa9bc;max-width:650px;line-height:1.8;font-size:14px}.buttons{display:flex;gap:10px;margin-top:24px}.button{display:inline-flex;padding:11px 16px;border-radius:8px;background:var(--green);color:#07231a;font-weight:750;border:0;cursor:pointer;font-size:12px}.button.secondary{background:#121d2b;border:1px solid #2b3a4c;color:#e5edf7}.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:7px 0 34px}.stat,.card,.toolbox,.result,.about{background:linear-gradient(145deg,#111b2a,#0e1724);border:1px solid var(--line);border-radius:12px}.stat{padding:15px 17px;display:flex;justify-content:space-between;align-items:center;color:var(--muted);font-size:11px}.stat strong{font-size:20px;color:var(--text)}.stat i{font-style:normal;color:var(--green)}.sectionhead{display:flex;justify-content:space-between;align-items:end;margin:30px 0 15px}.sectionhead h2{font-size:18px;margin:0 0 5px}.sectionhead p{margin:0;color:var(--muted);font-size:11px}.sectionhead span{color:#75849a;font-size:10px}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.card{padding:17px;transition:.2s;min-height:140px}.card:hover{border-color:#3d7169;transform:translateY(-2px);background:linear-gradient(145deg,#152538,#111c29)}.cardtop{display:flex;justify-content:space-between;align-items:center}.toolicon{width:34px;height:34px;display:grid;place-items:center;background:#14332e;border-radius:9px;color:var(--green);font-size:17px}.arrow{color:#6e7e91}.card h3{font-size:13px;margin:15px 0 6px}.card p{color:var(--muted);font-size:10px;line-height:1.6;margin:0}.toolbox{max-width:740px;margin:25px 0;padding:25px}.toolbox h2{margin:8px 0;font-size:25px}.toolbox>p{color:var(--muted);line-height:1.7;font-size:13px}.field{margin:18px 0}.field label{display:block;font-size:11px;color:#c4cfdd;margin-bottom:8px}.field input,.field textarea,.field select{display:block;width:100%;border:1px solid #2b3a4c;border-radius:8px;padding:12px;background:#0a111d;color:var(--text);font:13px inherit;outline:none}.field input:focus,.field textarea:focus,.field select:focus{border-color:#3fd9a0}.field textarea{min-height:110px;resize:vertical}.hint{font-size:10px;color:var(--muted);margin-top:6px}.result{max-width:740px;padding:20px;margin-top:14px;border-color:#265846;line-height:1.7}.result h3{color:var(--green);margin:0 0 8px}.result p{margin:5px 0;font-size:13px}.result ul{padding-left:20px;color:#bdc9d8;font-size:12px}.result.warn{border-color:#6a4b29}.result.warn h3{color:var(--amber)}.result.bad{border-color:#743d49}.result.bad h3{color:var(--red)}.about{padding:21px;margin-top:20px;max-width:740px}.about h3{font-size:14px;margin-top:0}.about p{font-size:12px;line-height:1.8;color:var(--muted)}footer{border-top:1px solid var(--line);margin-top:42px;padding-top:17px;color:#64748a;font-size:10px;display:flex;justify-content:space-between}.footerbrand{color:#b4c1d0}.mono{font-family:Consolas,monospace;overflow-wrap:anywhere}.quiz label{display:block;padding:9px 0;color:#bbc8d7;font-size:12px}.quiz input{margin-right:7px} @media(max-width:900px){.layout{grid-template-columns:1fr}.side{padding:12px 16px;border-right:0;border-bottom:1px solid var(--line)}.brand{padding:0}.navlabel,.privacy{display:none}.nav{display:flex;overflow:auto;margin-top:12px}.nav a{white-space:nowrap;padding:8px}.main{padding-top:12px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:560px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:1fr}.hero{padding-top:30px}.top span:last-child{display:none}.toolbox{padding:18px}footer{gap:12px;flex-direction:column}}
        """;

    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", CyberSecurityScanner::handle);
        server.setExecutor(null);
        server.start();
        System.out.println("Cyber Security Scanner running at http://localhost:" + port);
    }

    private static void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        Map<String, String> data = new LinkedHashMap<>();
        if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            byte[] body = exchange.getRequestBody().readNBytes(12 * 1024 * 1024);
            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            if (contentType != null && contentType.startsWith("multipart/form-data;")) parseMultipart(body, contentType, data);
            else {
                String encoded = new String(body, StandardCharsets.UTF_8);
                for (String pair : encoded.split("&")) {
                    String[] parts = pair.split("=", 2);
                    if (parts.length == 2) data.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8), URLDecoder.decode(parts[1], StandardCharsets.UTF_8));
                }
            }
        }
        int index = -1;
        if (path.startsWith("/tool/")) try { index = Integer.parseInt(path.substring(6)); } catch (NumberFormatException ignored) { }
        String content = index >= 0 && index < TOOLS.length ? toolPage(index, data) : homePage();
        byte[] response = content.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("X-Frame-Options", "DENY");
        exchange.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
        exchange.sendResponseHeaders(200, response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
    }

    private static void parseMultipart(byte[] body, String contentType, Map<String, String> data) {
        int boundaryStart = contentType.indexOf("boundary=");
        if (boundaryStart < 0) return;
        String boundary = "--" + contentType.substring(boundaryStart + 9).replace("\"", "").trim();
        String raw = new String(body, StandardCharsets.ISO_8859_1);
        for (String part : raw.split(Pattern.quote(boundary))) {
            int headerEnd = part.indexOf("\r\n\r\n");
            if (headerEnd < 0) continue;
            String headers = part.substring(0, headerEnd);
            var matcher = Pattern.compile("name=\"([^\"]+)\"").matcher(headers);
            if (!matcher.find()) continue;
            String value = part.substring(headerEnd + 4);
            if (value.endsWith("\r\n")) value = value.substring(0, value.length() - 2);
            if (headers.contains("filename=\"")) data.put(matcher.group(1), Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.ISO_8859_1)));
            else data.put(matcher.group(1), value);
        }
    }

    private static String shell(String title, String body, int active) {
        StringBuilder nav = new StringBuilder();
        for (int i = 0; i < TOOLS.length; i++) nav.append("<a class=\"").append(active == i ? "active" : "").append("\" href=\"/tool/").append(i).append("\"><span class=\"navicon\">").append(ICONS[i]).append("</span>").append(esc(TOOLS[i])).append("</a>");
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"theme-color\" content=\"#080d19\"><title>" + esc(title) + " · CyberShield</title><style>" + CSS + "</style></head><body><div class=\"layout\"><aside class=\"side\"><a class=\"brand\" href=\"/\"><span class=\"brandmark\">⌑</span><span>CyberShield<small>SECURITY TOOLKIT</small></span></a><div class=\"navlabel\">ANALYSIS TOOLS</div><nav class=\"nav\"><a class=\"" + (active == -1 ? "active" : "") + "\" href=\"/\"><span class=\"navicon\">⌂</span>Overview</a>" + nav + "</nav><div class=\"privacy\"><strong>◉ &nbsp;Local analysis</strong>Inputs are processed by this Java app and are not saved.</div></aside><main class=\"main\"><div class=\"top\"><span>Cybersecurity awareness toolkit</span><span class=\"live\"><i class=\"dot\"></i> JAVA ENGINE &nbsp;·&nbsp; ONLINE</span></div>" + body + "<footer><span class=\"footerbrand\">⌑ &nbsp;CyberShield <span style=\"color:#65748a\"> · Student project</span></span><span>Built with Java · Educational use only</span></footer></main></div></body></html>";
    }

    private static String homePage() {
        StringBuilder cards = new StringBuilder();
        for (int i = 0; i < TOOLS.length; i++) cards.append("<a class=\"card\" href=\"/tool/").append(i).append("\"><div class=\"cardtop\"><span class=\"toolicon\">").append(ICONS[i]).append("</span><span class=\"arrow\">↗</span></div><h3>").append(esc(TOOLS[i])).append("</h3><p>").append(esc(descriptions(i))).append("</p></a>");
        String body = "<section class=\"hero\"><div class=\"eyebrow\">✳ &nbsp; YOUR PERSONAL SECURITY WORKSPACE</div><h1>Stay one step<br>ahead of <span>threats.</span></h1><p>A practical cybersecurity toolkit to inspect links, strengthen passwords and learn safer digital habits. Simple checks, useful guidance, all powered by Java.</p><div class=\"buttons\"><a class=\"button\" href=\"#tools\">Explore all tools &nbsp; →</a><a class=\"button secondary\" href=\"/tool/10\">Take awareness test</a></div></section><div class=\"stats\"><div class=\"stat\"><span>SECURITY TOOLS</span><strong>12</strong><i>●</i></div><div class=\"stat\"><span>BUILT WITH</span><strong>Java</strong><i>⌘</i></div><div class=\"stat\"><span>YOUR DATA</span><strong>Private</strong><i>◉</i></div></div><div class=\"sectionhead\" id=\"tools\"><div><h2>Security toolkit</h2><p>Choose a tool to get started with a quick security check.</p></div><span>12 TOOLS &nbsp;·&nbsp; ALL SYSTEMS READY</span></div><div class=\"grid\">" + cards + "</div><section class=\"about\"><h3>About this project</h3><p>The Cyber Security Scanner is a Java-based educational application that helps users identify common online security risks and improve their cybersecurity awareness. It demonstrates object-oriented programming, string processing, input validation, conditional statements, file handling and basic networking concepts. Its checks are heuristic and educational; results are guidance rather than a guarantee that something is safe.</p></section>";
        return shell("Overview", body, -1);
    }

    private static String descriptions(int i) {
        return switch (i) {
            case 0 -> "Check a URL for suspicious patterns and connection clues."; case 1 -> "Review length, variety and common password weaknesses."; case 2 -> "Look for common signs of a deceptive email or message."; case 3 -> "Validate an IPv4 address and inspect its address range."; case 4 -> "Compare a file's digest with a known checksum."; case 5 -> "Create a SHA-256 digest from text."; case 6 -> "Encrypt or decrypt text using AES."; case 7 -> "Inspect a QR destination or link for warning signs."; case 8 -> "Review security headers for a website you control."; case 9 -> "Estimate a simple risk score from selected practices."; case 10 -> "Practice identifying common phishing red flags."; default -> "Review login protections and safer authentication practices.";
        };
    }

    private static String toolPage(int i, Map<String, String> values) {
        String fields = fields(i, values);
        String result = "";
        if (!values.isEmpty()) try { result = analyze(i, values); } catch (Exception exception) { result = panel("Input needs attention", esc(exception.getMessage() == null ? "Please check your input and try again." : exception.getMessage()), "warn"); }
        String form = "<form class=\"toolbox\" method=\"post\" " + (i == 4 ? "enctype=\"multipart/form-data\" " : "") + "action=\"/tool/" + i + "\"><div class=\"eyebrow\">JAVA SECURITY MODULE &nbsp;·&nbsp; " + String.format("%02d", i + 1) + " / 12</div><h2>" + esc(TOOLS[i]) + "</h2><p>" + esc(descriptions(i)) + "</p>" + fields + "<button class=\"button\" type=\"submit\">Run analysis &nbsp; →</button></form>" + result + "<section class=\"about\"><h3>How to read this result</h3><p>This tool uses basic local rules for educational awareness. It does not query threat-intelligence databases and cannot certify a link, address or file as safe. Never enter a real password or secret key into a classroom demo.</p></section>";
        return shell(TOOLS[i], "<div class=\"sectionhead\"><div><h2><a href=\"/\">Toolkit</a> &nbsp; / &nbsp; " + esc(TOOLS[i]) + "</h2><p>Input is analyzed by your local Java server.</p></div><a class=\"button secondary\" href=\"/\">← All tools</a></div>" + form, i);
    }

    private static String field(String name, String label, String placeholder, String value, String hint) {
        return "<div class=\"field\"><label for=\"" + name + "\">" + label + "</label><input id=\"" + name + "\" name=\"" + name + "\" value=\"" + esc(value) + "\" placeholder=\"" + esc(placeholder) + "\" required>" + (hint.isEmpty() ? "" : "<div class=\"hint\">" + hint + "</div>") + "</div>";
    }

    private static String textarea(String name, String label, String placeholder, String value, String hint) {
        return "<div class=\"field\"><label for=\"" + name + "\">" + label + "</label><textarea id=\"" + name + "\" name=\"" + name + "\" placeholder=\"" + esc(placeholder) + "\" required>" + esc(value) + "</textarea>" + (hint.isEmpty() ? "" : "<div class=\"hint\">" + hint + "</div>") + "</div>";
    }

    private static String fields(int i, Map<String, String> v) {
        return switch (i) {
            case 0, 7 -> field("url", "Website or link URL", "https://example.com", v.getOrDefault("url", ""), "Only inspect links you are authorized to review.");
            case 1 -> field("password", "Sample password", "Enter a sample only", "", "For privacy, use a made-up example. Your entry is not echoed back.");
            case 2 -> textarea("message", "Email or message text", "Paste suspicious message text (remove personal information)", v.getOrDefault("message", ""), "Do not include private or confidential information.");
            case 3 -> field("ip", "IPv4 address", "192.0.2.1", v.getOrDefault("ip", ""), "This checks the address format and common private/reserved ranges.");
            case 4 -> "<div class=\"field\"><label for=\"file\">Choose a file</label><input id=\"file\" name=\"file\" type=\"file\" required></div>" + field("expected", "Expected SHA-256 (optional)", "Paste a trusted checksum to compare", v.getOrDefault("expected", ""), "File contents are read locally by this Java server and are not saved.");
            case 5 -> textarea("text", "Text to hash", "Enter text to create a SHA-256 digest", v.getOrDefault("text", ""), "SHA-256 is a one-way digest, not encryption.");
            case 6 -> "<div class=\"field\"><label for=\"action\">Operation</label><select id=\"action\" name=\"action\"><option value=\"encrypt\">Encrypt</option><option value=\"decrypt\">Decrypt</option></select></div>" + field("key", "Secret key", "Enter a passphrase", "", "Demo uses a SHA-256-derived AES key. Never use it for real secrets.") + textarea("text", "Text or Base64 ciphertext", "Enter text", v.getOrDefault("text", ""), "Encrypted output is Base64 encoded.");
            case 8 -> field("url", "Website URL", "https://example.com", v.getOrDefault("url", ""), "Checks a URL you control by making a basic HTTP request from this Java server.");
            case 9 -> "<div class=\"field\"><label><input type=\"checkbox\" name=\"mfa\" value=\"yes\"> I use multi-factor authentication</label><label><input type=\"checkbox\" name=\"updates\" value=\"yes\"> I install security updates promptly</label><label><input type=\"checkbox\" name=\"unique\" value=\"yes\"> I use unique passwords with a password manager</label><label><input type=\"checkbox\" name=\"backup\" value=\"yes\"> I keep a separate backup of important files</label></div>";
            case 10 -> quizFields();
            default -> "<div class=\"field\"><label><input type=\"checkbox\" name=\"mfa\" value=\"yes\"> Multi-factor authentication is enabled</label><label><input type=\"checkbox\" name=\"limit\" value=\"yes\"> Login attempts are rate-limited</label><label><input type=\"checkbox\" name=\"hash\" value=\"yes\"> Passwords are stored using a password-hashing function</label><label><input type=\"checkbox\" name=\"reset\" value=\"yes\"> Password reset links expire and are single-use</label><label><input type=\"checkbox\" name=\"session\" value=\"yes\"> Sessions expire and cookies use Secure and HttpOnly flags</label></div>";
        };
    }

    private static String quizFields() {
        String[] qs = {"The sender address is slightly misspelled.", "The message says your account will close in 10 minutes.", "A link's displayed text differs from its destination.", "The email asks you to share a one-time verification code."};
        StringBuilder out = new StringBuilder("<div class=\"field quiz\"><label>Which are warning signs? Select all that apply.</label>");
        for (int i = 0; i < qs.length; i++) out.append("<label><input type=\"checkbox\" name=\"q").append(i).append("\" value=\"yes\"> ").append(esc(qs[i])).append("</label>");
        return out.append("</div>").toString();
    }

    private static String analyze(int i, Map<String, String> v) throws Exception {
        return switch (i) {
            case 0, 7 -> scanUrl(v.get("url")); case 1 -> password(v.get("password")); case 2 -> phishing(v.get("message")); case 3 -> ip(v.get("ip")); case 4 -> fileHash(v); case 5 -> hash(v.get("text")); case 6 -> encrypt(v); case 8 -> headers(v.get("url")); case 9 -> risk(v); case 10 -> quiz(v); default -> login(v);
        };
    }

    private static String scanUrl(String input) throws Exception {
        URI uri = URI.create(input.trim().contains("://") ? input.trim() : "https://" + input.trim());
        String host = uri.getHost();
        if (host == null || host.isBlank()) throw new IllegalArgumentException("Enter a valid website address.");
        List<String> issues = new ArrayList<>();
        if (!"https".equalsIgnoreCase(uri.getScheme())) issues.add("The link does not use HTTPS encryption.");
        if (host.matches("[0-9.]+")) issues.add("The link uses a raw IP address instead of a recognizable domain.");
        if (host.contains("xn--")) issues.add("The domain uses internationalized encoding; check for look-alike characters.");
        if (host.split("\\.").length > 5) issues.add("The domain contains many subdomains.");
        if (host.contains("@") || uri.getUserInfo() != null) issues.add("The URL contains user information, which can disguise the actual destination.");
        if (input.matches("(?i).*https?%3a.*") || input.matches("(?i).*%40.*")) issues.add("The URL contains encoded characters that can obscure its destination.");
        if (issues.isEmpty()) issues.add("No basic URL pattern warnings found. This does not prove the site is trustworthy.");
        return panel(issues.size() == 1 && issues.get(0).startsWith("No basic") ? "No obvious pattern found" : "Review this link carefully", "<p><b>Host:</b> <span class=\"mono\">" + esc(host) + "</span></p>" + list(issues), issues.size() == 1 && issues.get(0).startsWith("No basic") ? "" : "warn");
    }

    private static String password(String pass) {
        int score = 0;
        if (pass.length() >= 12) score++; if (pass.length() >= 16) score++;
        if (pass.matches("(?s).*\\p{Lu}.*")) score++; if (pass.matches("(?s).*\\p{Ll}.*")) score++;
        if (pass.matches("(?s).*\\d.*")) score++; if (pass.matches("(?s).*[^\\p{L}\\d].*")) score++;
        List<String> tips = new ArrayList<>();
        if (pass.length() < 12) tips.add("Use at least 12 characters; a longer passphrase is better.");
        if (!pass.matches("(?s).*\\p{Lu}.*") || !pass.matches("(?s).*\\p{Ll}.*")) tips.add("Mix upper and lower case letters.");
        if (!pass.matches("(?s).*\\d.*[^\\p{L}\\d].*|.*[^\\p{L}\\d].*\\d.*")) tips.add("Add numbers and symbols.");
        if (pass.toLowerCase().matches(".*(password|123456|qwerty|letmein|admin).*")) { tips.add("Avoid common words and predictable sequences."); score = Math.min(score, 2); }
        String rating = score >= 5 ? "Strong" : score >= 3 ? "Moderate" : "Weak";
        if (tips.isEmpty()) tips.add("Use a unique password for every account and store it in a password manager.");
        return panel("Strength estimate: " + rating, "<p>Estimated criteria score: " + score + " / 6. Your password is not displayed.</p>" + list(tips), score >= 5 ? "" : "warn");
    }

    private static String phishing(String message) {
        String lower = message.toLowerCase(); List<String> hits = new ArrayList<>();
        String[][] terms = {{"urgent", "Urgent or immediate action language"}, {"suspend", "Threat of account suspension"}, {"verify", "Request to verify account details"}, {"password", "Request involving a password"}, {"gift card", "Gift-card payment request"}, {"wire transfer", "Wire-transfer request"}, {"click here", "Generic link prompt"}, {"one-time code", "Request involving a one-time code"}, {"won", "Unexpected prize claim"}, {"invoice", "Invoice or payment claim"}};
        for (String[] term : terms) if (lower.contains(term[0])) hits.add(term[1]);
        var matcher = Pattern.compile("(?i)https?://[^\\s<>]+|www\\.[^\\s<>]+").matcher(message);
        if (matcher.find()) hits.add("Contains a link; verify the destination independently before opening it.");
        return hits.isEmpty() ? panel("No common warning phrases detected", "<p>Automated phrase checks miss sophisticated scams. Verify the sender through a separate trusted channel.</p>", "") : panel("Potential warning signs: " + hits.size(), list(hits) + "<p>Do not open unexpected attachments, enter credentials through email links, or share verification codes.</p>", "warn");
    }

    private static String ip(String input) {
        String[] parts = input.trim().split("\\.");
        if (parts.length != 4) throw new IllegalArgumentException("Enter an IPv4 address with four numbers, such as 192.0.2.1.");
        int[] n = new int[4];
        for (int x = 0; x < 4; x++) try { if (parts[x].isEmpty() || parts[x].length() > 3) throw new NumberFormatException(); n[x] = Integer.parseInt(parts[x]); if (n[x] > 255) throw new NumberFormatException(); } catch (NumberFormatException e) { throw new IllegalArgumentException("Each IPv4 number must be between 0 and 255."); }
        boolean privateIp = n[0] == 10 || n[0] == 127 || n[0] == 0 || n[0] == 192 && n[1] == 168 || n[0] == 172 && n[1] >= 16 && n[1] <= 31 || n[0] == 169 && n[1] == 254;
        return panel("Valid IPv4 format", "<p>Address: <span class=\"mono\">" + esc(input) + "</span></p><p>Classification: " + (privateIp ? "Private, loopback or link-local range" : "Not in the common private IPv4 ranges") + "</p><p>IP addresses can be shared, reassigned or masked; this local check does not identify an owner or location.</p>", privateIp ? "" : "warn");
    }

    private static String fileHash(Map<String, String> v) throws Exception {
        String encoded = v.get("file"); if (encoded == null || encoded.isBlank()) throw new IllegalArgumentException("Select a file and submit again.");
        byte[] bytes = Base64.getDecoder().decode(encoded); byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes); String actual = HexFormat.of().formatHex(digest); String expected = v.getOrDefault("expected", "").trim().toLowerCase();
        String detail = "<p>SHA-256: <span class=\"mono\">" + actual + "</span></p>";
        if (!expected.isEmpty()) { boolean match = actual.equals(expected); return panel(match ? "Checksum matches" : "Checksum does not match", detail + "<p>Compare only against a checksum from a trusted source.</p>", match ? "" : "bad"); }
        return panel("File fingerprint generated", detail + "<p>Save this value and compare it later to check whether the file has changed.</p>", "");
    }

    private static String hash(String text) throws Exception {
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        return panel("SHA-256 digest", "<p class=\"mono\">" + digest + "</p><p>A digest cannot be reversed to recover the original text.</p>", "");
    }

    private static String encrypt(Map<String, String> v) throws Exception {
        byte[] keyBytes = MessageDigest.getInstance("SHA-256").digest(v.get("key").getBytes(StandardCharsets.UTF_8));
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES"); Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        if ("decrypt".equals(v.get("action"))) { byte[] packed = Base64.getDecoder().decode(v.get("text")); byte[] iv = java.util.Arrays.copyOfRange(packed, 0, 12); cipher.init(Cipher.DECRYPT_MODE, key, new javax.crypto.spec.GCMParameterSpec(128, iv)); String plain = new String(cipher.doFinal(packed, 12, packed.length - 12), StandardCharsets.UTF_8); return panel("Decryption complete", "<p class=\"mono\">" + esc(plain) + "</p>", ""); }
        byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv); cipher.init(Cipher.ENCRYPT_MODE, key, new javax.crypto.spec.GCMParameterSpec(128, iv)); byte[] encrypted = cipher.doFinal(v.get("text").getBytes(StandardCharsets.UTF_8)); byte[] packed = new byte[iv.length + encrypted.length]; System.arraycopy(iv, 0, packed, 0, iv.length); System.arraycopy(encrypted, 0, packed, iv.length, encrypted.length);
        return panel("Encryption complete", "<p class=\"mono\">" + Base64.getEncoder().encodeToString(packed) + "</p><p>Keep the passphrase safe; losing it prevents decryption.</p>", "");
    }

    private static String headers(String input) throws Exception {
        URI uri = URI.create(input.trim().contains("://") ? input.trim() : "https://" + input.trim()); if (uri.getHost() == null || !(uri.getScheme().equals("https") || uri.getScheme().equals("http"))) throw new IllegalArgumentException("Enter a valid HTTP or HTTPS website URL.");
        var connection = uri.toURL().openConnection(); connection.setConnectTimeout(4000); connection.setReadTimeout(4000); connection.setRequestProperty("User-Agent", "CyberShield-Student-Project/1.0"); connection.connect();
        List<String> found = new ArrayList<>(); List<String> missing = new ArrayList<>();
        String[] checks = {"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"};
        for (String header : checks) { String value = connection.getHeaderField(header); if (value == null) missing.add(header); else found.add(header + ": " + value); }
        return panel("Security header review", "<p>Response status: " + (connection instanceof java.net.HttpURLConnection h ? h.getResponseCode() : "connected") + "</p><p><b>Present</b></p>" + (found.isEmpty() ? "<p>None of the checked headers were present.</p>" : list(found)) + "<p><b>Missing from this response</b></p>" + list(missing) + "<p>Headers can vary by route and response; this is a basic check, not a full audit.</p>", missing.isEmpty() ? "" : "warn");
    }

    private static String risk(Map<String, String> v) {
        String[] keys = {"mfa", "updates", "unique", "backup"}; int points = 0; for (String key : keys) if ("yes".equals(v.get(key))) points += 25;
        return panel("Security habits score: " + points + " / 100", "<p>Self-assessment based on the practices selected above.</p>" + list(List.of("Enable multi-factor authentication on important accounts.", "Install operating-system and application updates promptly.", "Use unique passwords stored in a password manager.", "Keep a separate, tested backup of important files.")), points >= 75 ? "" : "warn");
    }

    private static String quiz(Map<String, String> v) {
        int score = 0; for (int i = 0; i < 4; i++) if ("yes".equals(v.get("q" + i))) score++;
        return panel("Awareness score: " + score + " / 4", "<p>All four examples are warning signs. Check sender addresses carefully, avoid rushed requests, inspect link destinations, and never disclose one-time codes.</p>", score == 4 ? "" : "warn");
    }

    private static String login(Map<String, String> v) {
        String[] keys = {"mfa", "limit", "hash", "reset", "session"}; int points = 0; for (String key : keys) if ("yes".equals(v.get(key))) points += 20;
        return panel("Login protections: " + points + " / 100", "<p>For an application you own, confirm each selected control in the implementation. This checklist does not attempt to log in or test another system.</p>" + list(List.of("Enable multi-factor authentication.", "Rate-limit failed login attempts and monitor abuse.", "Store passwords with a dedicated password-hashing algorithm such as Argon2id, scrypt or bcrypt.", "Use expiring, single-use password reset tokens.", "Expire sessions and protect cookies with Secure, HttpOnly and an appropriate SameSite setting.")), points >= 80 ? "" : "warn");
    }

    private static String panel(String title, String content, String style) { return "<section class=\"result " + style + "\"><h3>" + esc(title) + "</h3>" + content + "</section>"; }
    private static String list(List<String> items) { StringBuilder out = new StringBuilder("<ul>"); for (String item : items) out.append("<li>").append(esc(item)).append("</li>"); return out.append("</ul>").toString(); }
    private static String esc(String value) { return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;"); }
}
