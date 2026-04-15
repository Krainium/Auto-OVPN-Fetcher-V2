package main

import (
        "archive/zip"
        "bufio"
        "bytes"
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "net/url"
        "os"
        "path/filepath"
        "regexp"
        "strings"
        "time"
)

// ── colours ───────────────────────────────────────────────────────────────────

const (
        Reset   = "\033[0m"
        Bold    = "\033[1m"
        Grey    = "\033[90m"
        Red     = "\033[91m"
        Green   = "\033[92m"
        Yellow  = "\033[93m"
        Blue    = "\033[94m"
        Magenta = "\033[95m"
        Cyan    = "\033[96m"
        White   = "\033[97m"
)

func oinfo(msg string)    { fmt.Printf("%s  [%s*%s%s]%s %s\n", Cyan, Bold, Reset, Cyan, Reset, msg) }
func osuccess(msg string) { fmt.Printf("%s  [%s+%s%s]%s %s%s%s\n", Green, Bold, Reset, Green, Reset, Green, msg, Reset) }
func owarn(msg string)    { fmt.Printf("%s  [%s!%s%s]%s %s%s%s\n", Yellow, Bold, Reset, Yellow, Reset, Yellow, msg, Reset) }
func oerror(msg string)   { fmt.Printf("%s  [%s-%s%s]%s %s%s%s\n", Red, Bold, Reset, Red, Reset, Red, msg, Reset) }
func ostep(msg string)    { fmt.Printf("%s  [%s>%s%s]%s %s%s%s%s\n", Magenta, Bold, Reset, Magenta, Reset, White, Bold, msg, Reset) }
func odetail(msg string)  { fmt.Printf("%s      %s%s\n", Grey, msg, Reset) }
func odivider()           { fmt.Printf("%s  %s%s\n", Grey, strings.Repeat("─", 62), Reset) }

func oheader(title string) {
        fmt.Println()
        odivider()
        fmt.Printf("  %s%s%s%s\n", Bold, White, title, Reset)
        odivider()
        fmt.Println()
}

func printBanner() {
        fmt.Printf(`
%s  +==============================================================+%s
%s  |%s  %s%s  ___  __   __ ____  _   _    ____  %s              %s|%s
%s  |%s  %s%s / _ \ \ \ / /|  _ \| \ | |  |___ \ %s             %s|%s
%s  |%s  %s%s| | | | \ V / | |_) |  \| |    __) |%s             %s|%s
%s  |%s  %s%s| |_| |  \_/  |  __/| |\  |   / __/ %s             %s|%s
%s  |%s  %s%s \___/        |_|   |_| \_|  |_____|%s              %s|%s
%s  |%s                                                              %s|%s
%s  |%s  %sMulti-Source VPN Config Fetcher%s  %sgithub.com/krainium%s  %s|%s
%s  +==============================================================+%s
`,
                Cyan, Reset,
                Cyan, Reset, Yellow, Bold, Reset, Cyan, Reset,
                Cyan, Reset, Yellow, Bold, Reset, Cyan, Reset,
                Cyan, Reset, Yellow, Bold, Reset, Cyan, Reset,
                Cyan, Reset, Yellow, Bold, Reset, Cyan, Reset,
                Cyan, Reset, Yellow, Bold, Reset, Cyan, Reset,
                Cyan, Reset, Cyan, Reset,
                Cyan, Reset, White, Reset, Grey, Reset, Cyan, Reset,
                Cyan, Reset,
        )
        odivider()
        fmt.Println()
}

// ── config record ─────────────────────────────────────────────────────────────

type VPNConfig struct {
        Name     string
        Country  string
        Source   string
        Protocol string
        Port     string
        Username string
        Password string
        Host     string
        OVPNData []byte
}

// ── http helper ───────────────────────────────────────────────────────────────

var httpClient = &http.Client{Timeout: 30 * time.Second}

const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"

func httpGet(rawURL string) ([]byte, error) {
        req, err := http.NewRequest("GET", rawURL, nil)
        if err != nil {
                return nil, err
        }
        req.Header.Set("User-Agent", ua)
        req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
        resp, err := httpClient.Do(req)
        if err != nil {
                return nil, err
        }
        defer resp.Body.Close()
        if resp.StatusCode >= 400 {
                return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
        }
        return io.ReadAll(resp.Body)
}

func extractZip(data []byte) (map[string][]byte, error) {
        r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
        if err != nil {
                return nil, err
        }
        out := map[string][]byte{}
        for _, f := range r.File {
                name := strings.ToLower(f.Name)
                if strings.HasSuffix(name, ".ovpn") || strings.HasSuffix(name, ".conf") {
                        rc, err := f.Open()
                        if err != nil {
                                continue
                        }
                        content, _ := io.ReadAll(rc)
                        rc.Close()
                        if len(content) > 20 {
                                out[filepath.Base(f.Name)] = content
                        }
                }
        }
        return out, nil
}

func truncate(s string, n int) string {
        if len(s) <= n {
                return s
        }
        return s[:n-1] + "…"
}

// ── SOURCE 1: VPNBook ─────────────────────────────────────────────────────────
//
// Real REST API:  GET https://www.vpnbook.com/api/openvpn?hostname=X&protocol=Y
// Protocols:      tcp443  tcp80  udp53  udp25000
// Servers:        scraped from https://www.vpnbook.com/freevpn (X.vpnbook.com hostnames)
// Password:       scraped from <code> elements — filter out crypto wallet addresses
// Username:       always "vpnbook"

var vpnbookProtocols = []struct{ proto, port string }{
        {"tcp443", "443"},
        {"tcp80", "80"},
        {"udp53", "53"},
        {"udp25000", "25000"},
}

func scrapeVPNBook() ([]string, string) {
        // credentials page is /freevpn/openvpn — code elements appear in order:
        //   vpnbook   (username — skip)
        //   ta2ktp6   (password — first short non-crypto value)
        //   <BTC/ETH/LTC addresses> ...
        body, err := httpGet("https://www.vpnbook.com/freevpn/openvpn")
        if err != nil {
                return vpnbookKnownServers, ""
        }
        html := string(body)

        // server hostnames — pattern X.vpnbook.com
        hostRe := regexp.MustCompile(`([a-z0-9]+\.vpnbook\.com)`)
        matches := hostRe.FindAllStringSubmatch(html, -1)
        seen := map[string]bool{}
        var servers []string
        for _, m := range matches {
                h := strings.ToLower(m[1])
                if !seen[h] && !strings.Contains(h, "www") {
                        seen[h] = true
                        servers = append(servers, h)
                }
        }
        if len(servers) == 0 {
                servers = vpnbookKnownServers
        }

        // password — skip username "vpnbook" and crypto wallet addresses;
        // the password is always the first short (≤20 char) remaining value
        codeRe := regexp.MustCompile(`<code[^>]*>([^<]{4,60})</code>`)
        codeTags := codeRe.FindAllStringSubmatch(html, -1)
        password := ""
        for _, m := range codeTags {
                val := strings.TrimSpace(m[1])
                if val == "" || val == "vpnbook" {
                        continue
                }
                // skip crypto wallet addresses
                if strings.HasPrefix(val, "bc1") || // Bitcoin bech32
                        strings.HasPrefix(val, "0x") || // Ethereum
                        strings.HasPrefix(val, "1") || strings.HasPrefix(val, "3") || // Bitcoin legacy
                        strings.HasPrefix(val, "L") || strings.HasPrefix(val, "M") { // Litecoin
                        continue
                }
                // password is always short; skip long donation strings
                if len(val) <= 20 {
                        password = val
                        break
                }
        }

        return servers, password
}

// fallback list scraped as of build time — will be updated at runtime
var vpnbookKnownServers = []string{
        "us16.vpnbook.com", "us178.vpnbook.com",
        "ca149.vpnbook.com", "ca196.vpnbook.com", "ca225.vpnbook.com",
        "fr200.vpnbook.com", "fr2311.vpnbook.com",
        "de20.vpnbook.com", "de220.vpnbook.com",
        "pl134.vpnbook.com", "pl140.vpnbook.com",
        "uk68.vpnbook.com", "uk205.vpnbook.com",
}

// embedCredentials replaces a bare "auth-user-pass" line in an OVPN config
// with the OpenVPN inline credentials block so the user never needs to supply
// --auth-user-pass at connect time.
func embedCredentials(data []byte, username, password string) []byte {
        lines := strings.Split(string(data), "\n")
        var out []string
        for _, line := range lines {
                trimmed := strings.TrimSpace(line)
                // match only a bare "auth-user-pass" with no filename argument
                if trimmed == "auth-user-pass" {
                        out = append(out,
                                "<auth-user-pass>",
                                username,
                                password,
                                "</auth-user-pass>",
                        )
                } else {
                        out = append(out, line)
                }
        }
        return []byte(strings.Join(out, "\n"))
}

func hostToCountry(host string) string {
        prefix := regexp.MustCompile(`^([a-z]+)`).FindString(host)
        m := map[string]string{
                "us": "United States", "ca": "Canada", "fr": "France",
                "de": "Germany", "pl": "Poland", "uk": "United Kingdom",
        }
        if c, ok := m[prefix]; ok {
                return c
        }
        return strings.ToUpper(prefix)
}

func fetchVPNBook() ([]VPNConfig, error) {
        ostep("VPNBook: fetching server list from /freevpn ...")
        servers, password := scrapeVPNBook()

        if password == "" {
                owarn("VPNBook: password not found in page — configs saved without credentials")
                owarn(fmt.Sprintf("         Get the current password at: %shttps://www.vpnbook.com/freevpn%s", Cyan, Reset))
        } else {
                osuccess(fmt.Sprintf("VPNBook: credentials — user=%svpnbook%s  pass=%s%s%s",
                        White, Reset, Yellow, password, Reset))
        }
        oinfo(fmt.Sprintf("VPNBook: %d servers × %d protocols = %d configs to fetch",
                len(servers), len(vpnbookProtocols), len(servers)*len(vpnbookProtocols)))

        var configs []VPNConfig
        for _, host := range servers {
                for _, p := range vpnbookProtocols {
                        apiURL := fmt.Sprintf("https://www.vpnbook.com/api/openvpn?hostname=%s&protocol=%s",
                                url.QueryEscape(host), p.proto)
                        data, err := httpGet(apiURL)
                        if err != nil {
                                // 503 = server doesn't support this protocol — expected, skip silently
                                if !strings.Contains(err.Error(), "HTTP 503") {
                                        owarn(fmt.Sprintf("skipped %s/%s: %s", host, p.proto, err))
                                }
                                continue
                        }
                        // check it's an actual config, not an error JSON
                        if !bytes.Contains(data, []byte("remote")) {
                                continue
                        }
                        // embed credentials inline so the user only needs: openvpn --config <file>
                        if password != "" {
                                data = embedCredentials(data, "vpnbook", password)
                        }
                        proto := "TCP"
                        if strings.HasPrefix(p.proto, "udp") {
                                proto = "UDP"
                        }
                        name := fmt.Sprintf("vpnbook_%s_%s.ovpn", strings.ReplaceAll(host, ".vpnbook.com", ""), p.proto)
                        configs = append(configs, VPNConfig{
                                Name:     name,
                                Country:  hostToCountry(host),
                                Source:   "VPNBook",
                                Protocol: proto,
                                Port:     p.port,
                                Username: "vpnbook",
                                Password: password,
                                Host:     host,
                                OVPNData: data,
                        })
                        odetail(fmt.Sprintf("%s%-30s%s %s%s/%s%s", Grey, name, Reset, Blue, proto, p.port, Reset))
                }
        }
        return configs, nil
}

// ── SOURCE 2: VPNJantit ───────────────────────────────────────────────────────
//
// Config download:  GET https://www.vpnjantit.com/download-openvpn.php?server=X
// Returns:          ZIP file containing .ovpn file(s)
// Servers:          scraped from country pages
// Auth:             account creation at /create-free-account?server=X (manual, 7-day TTL)

var vpnjantitBase = "https://www.vpnjantit.com"

var vpnjantitPages = []struct{ country, slug string }{
        {"Japan", "japan"},
        {"United States", "united-states"},
        {"Singapore", "singapore"},
        {"Indonesia", "indonesia"},
        {"Philippines", "philippines"},
        {"Thailand", "thailand"},
        {"South Korea", "south-korea"},
        {"Vietnam", "vietnam"},
        {"India", "india"},
        {"Germany", "germany"},
        {"United Kingdom", "united-kingdom"},
        {"France", "france"},
        {"Canada", "canada"},
        {"Australia", "australia"},
        {"Brazil", "brazil"},
        {"Russia", "russia"},
        {"Netherlands", "netherlands"},
        {"Turkey", "turkey"},
}

func scrapeVPNJantitCountry(country, slug string) []string {
        pageURL := fmt.Sprintf("%s/free-openvpn-%s", vpnjantitBase, slug)
        body, err := httpGet(pageURL)
        if err != nil {
                return nil
        }
        html := string(body)
        // pattern: href=/download-openvpn.php?server=JP1
        re := regexp.MustCompile(`(?i)/download-openvpn\.php\?server=([A-Za-z0-9]+)`)
        matches := re.FindAllStringSubmatch(html, -1)
        seen := map[string]bool{}
        var servers []string
        for _, m := range matches {
                id := strings.ToLower(m[1])
                if !seen[id] {
                        seen[id] = true
                        servers = append(servers, m[1]) // preserve original case for the API
                }
        }
        return servers
}

func fetchVPNJantit() ([]VPNConfig, error) {
        ostep("VPNJantit: scraping country pages for server IDs ...")
        odetail(fmt.Sprintf("Checking %d country pages", len(vpnjantitPages)))

        var configs []VPNConfig
        for i, page := range vpnjantitPages {
                odetail(fmt.Sprintf("[%d/%d] %s", i+1, len(vpnjantitPages), page.country))
                serverIDs := scrapeVPNJantitCountry(page.country, page.slug)
                if len(serverIDs) == 0 {
                        continue
                }

                for _, sid := range serverIDs {
                        dlURL := fmt.Sprintf("%s/download-openvpn.php?server=%s", vpnjantitBase, sid)
                        data, err := httpGet(dlURL)
                        if err != nil || len(data) < 20 {
                                continue
                        }

                        // VPNJantit returns a ZIP — extract .ovpn files
                        files, err := extractZip(data)
                        if err != nil || len(files) == 0 {
                                // might already be raw .ovpn
                                if bytes.Contains(data, []byte("remote")) {
                                        name := fmt.Sprintf("vjantit_%s_%s.ovpn", strings.ToLower(page.country[:2]), strings.ToLower(sid))
                                        configs = append(configs, VPNConfig{
                                                Name:     name,
                                                Country:  page.country,
                                                Source:   "VPNJantit",
                                                Protocol: "TCP",
                                                Port:     "443",
                                                OVPNData: data,
                                        })
                                        odetail(fmt.Sprintf("  %s%s%s (%s)", Grey, sid, Reset, page.country))
                                }
                                continue
                        }

                        for fname, content := range files {
                                proto := "TCP"
                                port := "1194"
                                fl := strings.ToLower(fname)
                                if strings.Contains(fl, "udp") {
                                        proto = "UDP"
                                }
                                if strings.Contains(fl, "443") {
                                        port = "443"
                                }
                                name := fmt.Sprintf("vjantit_%s_%s_%s.ovpn",
                                        strings.ToLower(strings.ReplaceAll(page.country, " ", "_")),
                                        strings.ToLower(sid), proto)
                                configs = append(configs, VPNConfig{
                                        Name:     name,
                                        Country:  page.country,
                                        Source:   "VPNJantit",
                                        Protocol: proto,
                                        Port:     port,
                                        OVPNData: content,
                                })
                                odetail(fmt.Sprintf("  %s%s%s → %s (%s)", Grey, sid, Reset, fname, page.country))
                        }
                }
        }

        if len(configs) > 0 {
                fmt.Println()
                owarn("VPNJantit: configs downloaded but require an account to connect")
                owarn(fmt.Sprintf("           Create one free at: %shttps://www.vpnjantit.com/free-openvpn%s", Cyan, Reset))
                owarn("           Accounts are free and expire after 7 days")
        }
        return configs, nil
}

// ── SOURCE 3 & 4: FreeOpenVPN + IPSpeed (via Zoult GitHub mirror) ─────────────
//
// GitHub repo:     https://github.com/Zoult/.ovpn
// API:             https://api.github.com/repos/Zoult/.ovpn/contents/<Country>
// Raw download:    https://raw.githubusercontent.com/Zoult/.ovpn/main/<Country>/<file>
// FOV_ prefix:     FreeOpenVPN.org configs
// IPS_ prefix:     IPSpeed.info configs
// Auth required:   FOV_ configs need vpnbook creds for some; IPS_ vary by server

var zoultCountries = []string{
        "Japan", "USA", "Canada", "France", "Germany", "Netherlands",
        "United Kingdom", "India", "Indonesia", "Italy", "Poland",
        "Romania", "Russia", "South Korea", "Sweden", "Thailand",
        "Turkey", "Ukraine", "Vietnam", "Emirates",
}

type githubFile struct {
        Name        string `json:"name"`
        DownloadURL string `json:"download_url"`
        Type        string `json:"type"`
}

func fetchZoultCountry(country, filterPrefix string) []VPNConfig {
        apiURL := fmt.Sprintf("https://api.github.com/repos/Zoult/.ovpn/contents/%s",
                url.PathEscape(country))
        data, err := httpGet(apiURL)
        if err != nil {
                return nil
        }

        var files []githubFile
        if err := json.Unmarshal(data, &files); err != nil {
                return nil
        }

        var configs []VPNConfig
        for _, f := range files {
                if f.Type != "file" || !strings.HasSuffix(strings.ToLower(f.Name), ".ovpn") {
                        continue
                }
                if filterPrefix != "" && !strings.HasPrefix(f.Name, filterPrefix) {
                        continue
                }
                if f.DownloadURL == "" {
                        continue
                }

                content, err := httpGet(f.DownloadURL)
                if err != nil || len(content) < 20 {
                        continue
                }
                if !bytes.Contains(content, []byte("remote")) {
                        continue
                }

                proto := "TCP"
                port := "443"
                fl := strings.ToLower(f.Name)
                if strings.Contains(fl, "udp") {
                        proto = "UDP"
                        port = "1194"
                }

                source := "FreeOpenVPN"
                if strings.HasPrefix(f.Name, "IPS_") {
                        source = "IPSpeed"
                }

                configs = append(configs, VPNConfig{
                        Name:     f.Name,
                        Country:  country,
                        Source:   source,
                        Protocol: proto,
                        Port:     port,
                        OVPNData: content,
                })
        }
        return configs
}

func fetchGitHubSource(label, prefix string) ([]VPNConfig, error) {
        ostep(fmt.Sprintf("%s: fetching from Zoult GitHub mirror (%d countries) ...", label, len(zoultCountries)))

        var all []VPNConfig
        for i, country := range zoultCountries {
                odetail(fmt.Sprintf("[%d/%d] %s", i+1, len(zoultCountries), country))
                configs := fetchZoultCountry(country, prefix)
                all = append(all, configs...)
        }
        return all, nil
}

// ── display ───────────────────────────────────────────────────────────────────

func sourceColor(source string) string {
        switch source {
        case "VPNBook":
                return Cyan
        case "VPNJantit":
                return Magenta
        case "FreeOpenVPN":
                return Yellow
        case "IPSpeed":
                return Green
        default:
                return White
        }
}

func printTable(configs []VPNConfig) {
        if len(configs) == 0 {
                owarn("No configs to display")
                return
        }
        oheader(fmt.Sprintf("VPN Configs  (%d total)  %s[all datacenter IPs]%s", len(configs), Grey, Reset))
        fmt.Printf("  %s%-4s  %-13s  %-22s  %-12s  %s%s\n",
                Bold+White, "#", "Source", "Country", "Protocol", "Filename", Reset)
        odivider()
        for i, c := range configs {
                sc := sourceColor(c.Source)
                protoStr := fmt.Sprintf("%s%s/%s%s", Blue, c.Protocol, c.Port, Reset)
                fmt.Printf("  %-4d  %s%-13s%s  %-22s  %-20s  %s%s%s\n",
                        i+1,
                        sc, c.Source, Reset,
                        truncate(c.Country, 22),
                        protoStr,
                        Grey, truncate(c.Name, 36), Reset,
                )
        }
        fmt.Println()
}

func printSummary(configs []VPNConfig) {
        counts := map[string]int{}
        countries := map[string]map[string]bool{}
        for _, c := range configs {
                counts[c.Source]++
                if countries[c.Source] == nil {
                        countries[c.Source] = map[string]bool{}
                }
                countries[c.Source][c.Country] = true
        }
        oheader("Fetch Summary")
        for src, n := range counts {
                sc := sourceColor(src)
                ctryCount := len(countries[src])
                fmt.Printf("  %s%-13s%s  %s%d configs%s  %s%d countries%s  %s[Datacenter]%s\n",
                        sc, src, Reset,
                        White, n, Reset,
                        Grey, ctryCount, Reset,
                        Red, Reset)
        }
        fmt.Println()
}

// ── filter ────────────────────────────────────────────────────────────────────

func filterBySource(configs []VPNConfig, src string) []VPNConfig {
        var out []VPNConfig
        for _, c := range configs {
                if strings.EqualFold(c.Source, src) {
                        out = append(out, c)
                }
        }
        return out
}

func filterByCountry(configs []VPNConfig, q string) []VPNConfig {
        q = strings.ToUpper(strings.TrimSpace(q))
        var out []VPNConfig
        for _, c := range configs {
                if strings.Contains(strings.ToUpper(c.Country), q) ||
                        strings.Contains(strings.ToUpper(c.Name), q) {
                        out = append(out, c)
                }
        }
        return out
}

// ── save ──────────────────────────────────────────────────────────────────────

func saveConfigs(configs []VPNConfig, outDir string) {
        if len(configs) == 0 {
                owarn("Nothing to save")
                return
        }
        if err := os.MkdirAll(outDir, 0755); err != nil {
                oerror("Cannot create directory: " + err.Error())
                return
        }
        oheader(fmt.Sprintf("Saving %d configs → %s%s%s", len(configs), Cyan, outDir, Reset))

        saved, failed := 0, 0

        for _, c := range configs {
                if len(c.OVPNData) == 0 {
                        continue
                }
                name := c.Name
                if name == "" {
                        name = fmt.Sprintf("%s_%s_%s.ovpn", c.Source, strings.ReplaceAll(c.Country, " ", "_"), c.Protocol)
                }
                path := filepath.Join(outDir, name)
                if err := os.WriteFile(path, c.OVPNData, 0644); err != nil {
                        oerror(fmt.Sprintf("%-36s  write failed: %s", name, err))
                        failed++
                        continue
                }

                sc := sourceColor(c.Source)
                credTag := ""
                if c.Source == "VPNBook" && c.Password != "" {
                        credTag = fmt.Sprintf("  %s[creds embedded]%s", Grey, Reset)
                }
                osuccess(fmt.Sprintf("%s%-11s%s  %-20s  %s%s/%s%s  → %s%s%s%s",
                        sc, c.Source, Reset,
                        truncate(c.Country, 20),
                        Blue, c.Protocol, c.Port, Reset,
                        Grey, filepath.Base(path), Reset,
                        credTag,
                ))
                saved++
        }

        fmt.Println()
        odivider()
        odetail(fmt.Sprintf("Saved    : %s%d%s", Green, saved, Reset))
        if failed > 0 {
                odetail(fmt.Sprintf("Failed   : %s%d%s", Red, failed, Reset))
        }
        odetail(fmt.Sprintf("Location : %s%s%s", Cyan, outDir, Reset))
        fmt.Println()

        if saved > 0 {
                osuccess(fmt.Sprintf("Connect:  %ssudo openvpn --config %s/<file>.ovpn%s", Yellow, outDir, Reset))
        }
}

// ── input ─────────────────────────────────────────────────────────────────────

var stdin = bufio.NewReader(os.Stdin)

func prompt(msg string) string {
        fmt.Printf("%s  %s›%s %s%s: %s", Cyan, Bold, Reset, White, msg, Reset)
        line, _ := stdin.ReadString('\n')
        return strings.TrimSpace(line)
}

func promptDir(fallback string) string {
        d := prompt(fmt.Sprintf("Output directory  [%s]", fallback))
        if d == "" {
                return fallback
        }
        return d
}

// ── menu ──────────────────────────────────────────────────────────────────────

func printMenu(loaded int) {
        fmt.Println()
        odivider()
        tag := "no configs loaded"
        if loaded > 0 {
                tag = fmt.Sprintf("%s%d configs in memory%s", White, loaded, Grey)
        }
        fmt.Printf("  %s%sMain Menu%s  %s(%s)%s\n", Bold, White, Reset, Grey, tag, Reset)
        odivider()
        fmt.Printf("  %s[1]%s  VPNBook       %s— REST API  /api/openvpn   [Datacenter]%s\n", Yellow, Reset, Grey, Reset)
        fmt.Printf("  %s[2]%s  VPNJantit     %s— ZIP config download      [Datacenter]%s\n", Yellow, Reset, Grey, Reset)
        fmt.Printf("  %s[3]%s  FreeOpenVPN   %s— GitHub mirror (FOV_)     [Datacenter]%s\n", Yellow, Reset, Grey, Reset)
        fmt.Printf("  %s[4]%s  IPSpeed       %s— GitHub mirror (IPS_)     [Datacenter]%s\n", Yellow, Reset, Grey, Reset)
        fmt.Printf("  %s[5]%s  All sources   %s— fetch everything%s\n", Yellow, Reset, Grey, Reset)
        odivider()
        fmt.Printf("  %s[6]%s  List current results\n", Yellow, Reset)
        fmt.Printf("  %s[7]%s  Save current results\n", Yellow, Reset)
        fmt.Printf("  %s[8]%s  Save split by source  %s(creates subfolders)%s\n", Yellow, Reset, Grey, Reset)
        fmt.Printf("  %s[9]%s  Filter by country keyword\n", Yellow, Reset)
        odivider()
        fmt.Printf("  %s[0]%s  %sQuit%s\n", Red, Reset, Red, Reset)
        odivider()
        fmt.Println()
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
        printBanner()

        fmt.Printf("  %s!%s  %sIP notice:%s  None of these sources provide residential IPs.\n", Yellow, Reset, Yellow, Reset)
        fmt.Printf("      %sAll exit nodes are datacenter. For residential-leaning nodes,\n", Grey)
        fmt.Printf("      %suse the %sovpn%s tool — VPNGate includes volunteer home connections.%s\n\n", Grey, White, Grey, Reset)

        var current []VPNConfig

        for {
                printMenu(len(current))
                choice := prompt("Select option")

                switch choice {

                case "1":
                        fmt.Println()
                        configs, err := fetchVPNBook()
                        if err != nil {
                                oerror(err.Error())
                                continue
                        }
                        if len(configs) == 0 {
                                owarn("VPNBook: no configs returned — the API may have changed")
                        } else {
                                current = configs
                                osuccess(fmt.Sprintf("VPNBook: %d configs loaded", len(configs)))
                                printTable(current)
                        }

                case "2":
                        fmt.Println()
                        configs, err := fetchVPNJantit()
                        if err != nil {
                                oerror(err.Error())
                                continue
                        }
                        if len(configs) == 0 {
                                owarn("VPNJantit: no configs found — site layout may have changed")
                                owarn(fmt.Sprintf("           Visit %shttps://www.vpnjantit.com/free-openvpn%s for manual download", Cyan, Reset))
                        } else {
                                current = configs
                                osuccess(fmt.Sprintf("VPNJantit: %d configs loaded", len(configs)))
                                printTable(current)
                        }

                case "3":
                        fmt.Println()
                        configs, err := fetchGitHubSource("FreeOpenVPN", "FOV_")
                        if err != nil {
                                oerror(err.Error())
                                continue
                        }
                        if len(configs) == 0 {
                                owarn("FreeOpenVPN: no configs found in GitHub mirror")
                        } else {
                                current = configs
                                osuccess(fmt.Sprintf("FreeOpenVPN: %d configs loaded", len(configs)))
                                printTable(current)
                        }

                case "4":
                        fmt.Println()
                        configs, err := fetchGitHubSource("IPSpeed", "IPS_")
                        if err != nil {
                                oerror(err.Error())
                                continue
                        }
                        if len(configs) == 0 {
                                owarn("IPSpeed: no configs found in GitHub mirror")
                        } else {
                                current = configs
                                osuccess(fmt.Sprintf("IPSpeed: %d configs loaded", len(configs)))
                                printTable(current)
                        }

                case "5":
                        fmt.Println()
                        ostep("Fetching all 4 sources ...")
                        fmt.Println()

                        var all []VPNConfig

                        c1, _ := fetchVPNBook()
                        all = append(all, c1...)
                        if len(c1) > 0 {
                                osuccess(fmt.Sprintf("VPNBook:      %s%d configs%s", White, len(c1), Reset))
                        } else {
                                owarn("VPNBook:      0 configs")
                        }

                        c2, _ := fetchVPNJantit()
                        all = append(all, c2...)
                        if len(c2) > 0 {
                                osuccess(fmt.Sprintf("VPNJantit:    %s%d configs%s", White, len(c2), Reset))
                        } else {
                                owarn("VPNJantit:    0 configs")
                        }

                        c3, _ := fetchGitHubSource("FreeOpenVPN", "FOV_")
                        all = append(all, c3...)
                        if len(c3) > 0 {
                                osuccess(fmt.Sprintf("FreeOpenVPN:  %s%d configs%s", White, len(c3), Reset))
                        } else {
                                owarn("FreeOpenVPN:  0 configs")
                        }

                        c4, _ := fetchGitHubSource("IPSpeed", "IPS_")
                        all = append(all, c4...)
                        if len(c4) > 0 {
                                osuccess(fmt.Sprintf("IPSpeed:      %s%d configs%s", White, len(c4), Reset))
                        } else {
                                owarn("IPSpeed:      0 configs")
                        }

                        if len(all) == 0 {
                                owarn("No configs returned from any source")
                                continue
                        }
                        current = all
                        printSummary(current)
                        printTable(current)

                case "6":
                        if len(current) == 0 {
                                owarn("No configs loaded — run [1]–[5] first")
                                continue
                        }
                        printTable(current)

                case "7":
                        if len(current) == 0 {
                                owarn("No configs loaded — run [1]–[5] first")
                                continue
                        }
                        outDir := promptDir("ovpn2_configs")
                        saveConfigs(current, outDir)

                case "8":
                        if len(current) == 0 {
                                owarn("No configs loaded — run [1]–[5] first")
                                continue
                        }
                        outDir := promptDir("ovpn2_configs")
                        for _, src := range []string{"VPNBook", "VPNJantit", "FreeOpenVPN", "IPSpeed"} {
                                subset := filterBySource(current, src)
                                if len(subset) == 0 {
                                        continue
                                }
                                saveConfigs(subset, filepath.Join(outDir, src))
                        }

                case "9":
                        if len(current) == 0 {
                                owarn("No configs loaded — run [1]–[5] first")
                                continue
                        }
                        q := prompt("Country name or keyword  e.g. Japan or US")
                        if q == "" {
                                owarn("No input")
                                continue
                        }
                        filtered := filterByCountry(current, q)
                        if len(filtered) == 0 {
                                owarn(fmt.Sprintf("No configs matched: %s%s%s", White, q, Reset))
                        } else {
                                printTable(filtered)
                        }

                case "0", "q", "Q", "quit", "exit":
                        fmt.Println()
                        osuccess("Goodbye.")
                        fmt.Println()
                        os.Exit(0)

                default:
                        owarn(fmt.Sprintf("Unknown option: %s%s%s — enter a number from the menu", White, choice, Reset))
                }
        }
}
