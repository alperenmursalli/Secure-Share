package org.example.secshare.vuln;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Merkezi zafiyet bayrak kaydi. application-vuln.properties icindeki
 * "vuln.*" ayarlarina baglanir. Her alan tek bir acigi kontrol eder;
 * hepsi false iken uygulama guvenli davranir.
 *
 * SADECE YETKILI PENTEST / EGITIM ORTAMI ICIN.
 */
@Component
@ConfigurationProperties(prefix = "vuln")
public class VulnProperties {

    /** Tum zafiyetli modullerin ana svici. false ise hicbiri devrede degil. */
    private boolean enabled = false;

    private final Jwt jwt = new Jwt();
    private final Auth auth = new Auth();
    private final Access access = new Access();
    private final Search search = new Search();
    private final File file = new File();
    private final Import imp = new Import();
    private final Process process = new Process();
    private final Serve serve = new Serve();
    private final Cors cors = new Cors();
    private final Errors errors = new Errors();

    public static class Jwt {
        /** Bilinen/zayif HMAC secret kullan (JWT forge -> privesc). */
        private boolean weakSecret = false;
        /** alg:none tokenlarini imzasiz kabul et. */
        private boolean allowNone = false;
        public boolean isWeakSecret() { return weakSecret; }
        public void setWeakSecret(boolean v) { this.weakSecret = v; }
        public boolean isAllowNone() { return allowNone; }
        public void setAllowNone(boolean v) { this.allowNone = v; }
    }

    public static class Auth {
        /** register/login farkli cevaplarla kullanici enumeration. */
        private boolean userEnum = false;
        /** login denemelerinde rate limit yok (brute force). */
        private boolean noRateLimit = false;
        /** register'da client'in gonderdigi roles alani kabul edilir (mass assignment). */
        private boolean massAssignment = false;
        public boolean isUserEnum() { return userEnum; }
        public void setUserEnum(boolean v) { this.userEnum = v; }
        public boolean isNoRateLimit() { return noRateLimit; }
        public void setNoRateLimit(boolean v) { this.noRateLimit = v; }
        public boolean isMassAssignment() { return massAssignment; }
        public void setMassAssignment(boolean v) { this.massAssignment = v; }
    }

    public static class Access {
        /** ownership check'siz legacy indirme endpoint'i (IDOR). */
        private boolean legacyDownload = false;
        public boolean isLegacyDownload() { return legacyDownload; }
        public void setLegacyDownload(boolean v) { this.legacyDownload = v; }
    }

    public static class Search {
        /** string birlestiren native sorgu (SQL injection). */
        private boolean sqli = false;
        public boolean isSqli() { return sqli; }
        public void setSqli(boolean v) { this.sqli = v; }
    }

    public static class File {
        /** normalize edilmeyen path ile ham dosya okuma (LFI/traversal). */
        private boolean pathTraversal = false;
        public boolean isPathTraversal() { return pathTraversal; }
        public void setPathTraversal(boolean v) { this.pathTraversal = v; }
    }

    public static class Import {
        /** sunucu tarafi URL fetch (SSRF). */
        private boolean ssrf = false;
        /** XML parser'da DTD/external entity acik (XXE). */
        private boolean xxe = false;
        /** SnakeYAML guvensiz load (CVE-2022-1471 sinifi deserialization RCE). */
        private boolean yaml = false;
        public boolean isSsrf() { return ssrf; }
        public void setSsrf(boolean v) { this.ssrf = v; }
        public boolean isXxe() { return xxe; }
        public void setXxe(boolean v) { this.xxe = v; }
        public boolean isYaml() { return yaml; }
        public void setYaml(boolean v) { this.yaml = v; }
    }

    public static class Process {
        /** Runtime.exec ile kabuk komutu (command injection / RCE). */
        private boolean cmdInjection = false;
        /** zip cikartirken entry adi dogrulanmaz (Zip Slip -> depo disina yazma). */
        private boolean zipSlip = false;
        public boolean isCmdInjection() { return cmdInjection; }
        public void setCmdInjection(boolean v) { this.cmdInjection = v; }
        public boolean isZipSlip() { return zipSlip; }
        public void setZipSlip(boolean v) { this.zipSlip = v; }
    }

    public static class Serve {
        /** dosyayi inline + kullanici content-type ile servis (stored XSS). */
        private boolean storedXss = false;
        public boolean isStoredXss() { return storedXss; }
        public void setStoredXss(boolean v) { this.storedXss = v; }
    }

    public static class Cors {
        /** Access-Control-Allow-Origin: * + credentials. */
        private boolean wildcard = false;
        public boolean isWildcard() { return wildcard; }
        public void setWildcard(boolean v) { this.wildcard = v; }
    }

    public static class Errors {
        /** hata cevaplarinda stacktrace/detay sizdir. */
        private boolean verbose = false;
        public boolean isVerbose() { return verbose; }
        public void setVerbose(boolean v) { this.verbose = v; }
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public Jwt getJwt() { return jwt; }
    public Auth getAuth() { return auth; }
    public Access getAccess() { return access; }
    public Search getSearch() { return search; }
    public File getFile() { return file; }
    public Import getImport() { return imp; }
    public Process getProcess() { return process; }
    public Serve getServe() { return serve; }
    public Cors getCors() { return cors; }
    public Errors getErrors() { return errors; }
}
