package main

import (
    "bufio"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
    "os/exec"
    "path/filepath"
    "strings"
)

// Config is the main structure of our JSON configuration file
type Config struct {
    OS                    string           `json:"os"`
    Firewall              FirewallConfig  `json:"firewall"`
    Users                 UserConfig      `json:"users"`
    SecurePasswordRules   PasswordConfig  `json:"secure_password_rules"`
    UnapprovedExtensions  []string        `json:"unapproved_extensions"`
    RemovePackages        []string        `json:"remove_packages"`
    DisablePacketForwarding bool          `json:"disable_packet_forwarding"`
    UpdatePackages        bool            `json:"update_packages"`
    CheckSudoersPermissions bool          `json:"check_sudoers_permissions"`
    ServicesToKeep        []string        `json:"services_to_keep"`
}

type FirewallConfig struct {
    Type  string `json:"type"` // e.g., "ufw", "iptables", or "none"
    Rules struct {
        TCPAllow []int `json:"tcp_allow"`
        TCPDeny  []int `json:"tcp_deny"`
        UDPAllow []int `json:"udp_allow"`
        UDPDeny  []int `json:"udp_deny"`
    } `json:"rules"`
}

type UserConfig struct {
    Authorized []string `json:"authorized"`
    SudoGroup  string   `json:"sudo_group"`
}

type PasswordConfig struct {
    UsePamPwquality bool `json:"use_pam_pwquality"`
    Minlen    int  `json:"minlen"`
    Difok     int  `json:"difok"`
    Ucredit   int  `json:"ucredit"`
    Lcredit   int  `json:"lcredit"`
    Dcredit   int  `json:"dcredit"`
    Ocredit   int  `json:"ocredit"`
    Retry     int  `json:"retry"`
}

// ------------------ Utility Functions ------------------ //

// runCommand executes a shell command and returns its output and error
func runCommand(command string) (string, error) {
    cmd := exec.Command("sh", "-c", command)
    output, err := cmd.CombinedOutput()
    return string(output), err
}

// verifyFileContent checks if a file contains the specified substring
func verifyFileContent(filePath, expectedContent string) bool {
    file, err := os.Open(filePath)
    if err != nil {
        return false
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        if strings.Contains(scanner.Text(), expectedContent) {
            return true
        }
    }
    return false
}

// verifyPermissions checks if a file has the expected permission (octal, e.g. "440")
func verifyPermissions(filePath, expectedPermissions string) bool {
    info, err := os.Stat(filePath)
    if err != nil {
        return false
    }
    mode := info.Mode().Perm()
    return fmt.Sprintf("%o", mode) == expectedPermissions
}

// ------------------ Main Hardening Functions ------------------ //

// ensureAuthorizedUsers can be extended to ensure only certain users exist
// or at least make sure the ones we need are present in the sudo group
func ensureAuthorizedUsers(cfg Config) {
    fmt.Println("Ensuring authorized users are in the correct group...")

    for _, user := range cfg.Users.Authorized {
        // Add user to sudo group if not already
        groupCheckCmd := fmt.Sprintf("getent group %s | grep %s", cfg.Users.SudoGroup, user)
        output, _ := runCommand(groupCheckCmd)
        if !strings.Contains(output, user) {
            fmt.Printf("User %s not in group %s. Adding now.\n", user, cfg.Users.SudoGroup)
            runCommand(fmt.Sprintf("sudo usermod -aG %s %s", cfg.Users.SudoGroup, user))
        }
    }
}

// ensureFirewallRules applies firewall rules based on config (UFW or IPTABLES)
func ensureFirewallRules(cfg Config) {
    if cfg.Firewall.Type == "" || cfg.Firewall.Type == "none" {
        fmt.Println("Firewall management is disabled or not specified.")
        return
    }

    fmt.Printf("Configuring firewall using: %s\n", cfg.Firewall.Type)

    switch cfg.Firewall.Type {
    case "ufw":
        // Deny all inbound by default (ufw default deny incoming)
        runCommand("ufw --force reset")
        runCommand("ufw default deny incoming")
        runCommand("ufw default deny outgoing")

        // Allow inbound TCP ports
        for _, port := range cfg.Firewall.Rules.TCPAllow {
            cmd := fmt.Sprintf("ufw allow %d/tcp", port)
            runCommand(cmd)
        }
        // Deny inbound TCP ports
        for _, port := range cfg.Firewall.Rules.TCPDeny {
            cmd := fmt.Sprintf("ufw deny %d/tcp", port)
            runCommand(cmd)
        }
        // Allow inbound UDP ports
        for _, port := range cfg.Firewall.Rules.UDPAllow {
            cmd := fmt.Sprintf("ufw allow %d/udp", port)
            runCommand(cmd)
        }
        // Deny inbound UDP ports
        for _, port := range cfg.Firewall.Rules.UDPDeny {
            cmd := fmt.Sprintf("ufw deny %d/udp", port)
            runCommand(cmd)
        }

        // We can also allow DNS outbound in general
        runCommand("ufw allow out 53/udp")
        runCommand("ufw allow out 53/tcp")

        // For demonstration, let's allow all outbound except what we explicitly block
        runCommand("ufw default allow outgoing")

        // Finally, enable UFW
        runCommand("ufw --force enable")

    case "iptables":
        // Flush existing rules
        runCommand("iptables -F")
        runCommand("iptables -X")
        runCommand("iptables -t nat -F")
        runCommand("iptables -t nat -X")
        runCommand("iptables -t mangle -F")
        runCommand("iptables -t mangle -X")

        // Default policies
        runCommand("iptables -P INPUT DROP")
        runCommand("iptables -P FORWARD DROP")
        runCommand("iptables -P OUTPUT DROP")

        // Allow loopback traffic
        runCommand("iptables -A INPUT -i lo -j ACCEPT")
        runCommand("iptables -A OUTPUT -o lo -j ACCEPT")

        // Allow inbound TCP ports
        for _, port := range cfg.Firewall.Rules.TCPAllow {
            cmd := fmt.Sprintf("iptables -A INPUT -p tcp --dport %d -j ACCEPT", port)
            runCommand(cmd)
        }
        // Deny inbound TCP ports (explicitly)
        for _, port := range cfg.Firewall.Rules.TCPDeny {
            cmd := fmt.Sprintf("iptables -A INPUT -p tcp --dport %d -j DROP", port)
            runCommand(cmd)
        }
        // Allow inbound UDP ports
        for _, port := range cfg.Firewall.Rules.UDPAllow {
            cmd := fmt.Sprintf("iptables -A INPUT -p udp --dport %d -j ACCEPT", port)
            runCommand(cmd)
        }
        // Deny inbound UDP ports
        for _, port := range cfg.Firewall.Rules.UDPDeny {
            cmd := fmt.Sprintf("iptables -A INPUT -p udp --dport %d -j DROP", port)
            runCommand(cmd)
        }

        // Example: Allow DNS outbound
        runCommand("iptables -A OUTPUT -p udp --dport 53 -j ACCEPT")
        runCommand("iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT")

        // Let all outbound except what is explicitly blocked (this is a simplification)
        runCommand("iptables -A OUTPUT -j ACCEPT")

        fmt.Println("Iptables rules applied.")
    default:
        fmt.Printf("Unknown firewall type: %s. Skipping firewall configuration.\n", cfg.Firewall.Type)
    }
}

// ensureSecurePasswordRules modifies /etc/pam.d/common-password or the relevant file
func ensureSecurePasswordRules(cfg Config) {
    if !cfg.SecurePasswordRules.UsePamPwquality {
        fmt.Println("Skipping pam_pwquality enforcement.")
        return
    }

    fmt.Println("Ensuring secure password rules...")

    // Example for Debian/Ubuntu systems
    // If RedHat, you might edit /etc/pam.d/system-auth or /etc/security/pwquality.conf
    pamFile := "/etc/pam.d/common-password"
    if _, err := os.Stat(pamFile); os.IsNotExist(err) {
        fmt.Printf("Warning: %s does not exist on this system.\n", pamFile)
        return
    }

    // Build the line we want to enforce
    // e.g. password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 ...
    rule := fmt.Sprintf("password requisite pam_pwquality.so retry=%d minlen=%d difok=%d ucredit=%d lcredit=%d dcredit=%d ocredit=%d",
        cfg.SecurePasswordRules.Retry,
        cfg.SecurePasswordRules.Minlen,
        cfg.SecurePasswordRules.Difok,
        cfg.SecurePasswordRules.Ucredit,
        cfg.SecurePasswordRules.Lcredit,
        cfg.SecurePasswordRules.Dcredit,
        cfg.SecurePasswordRules.Ocredit,
    )

    // Append if not already present
    if !verifyFileContent(pamFile, rule) {
        file, err := os.OpenFile(pamFile, os.O_APPEND|os.O_WRONLY, 0644)
        if err != nil {
            fmt.Println("Error opening common-password file:", err)
            return
        }
        defer file.Close()

        file.WriteString(rule + "\n")
        fmt.Println("Password policy updated in", pamFile)
    } else {
        fmt.Println("Password policy already in place.")
    }
}

// removeUnapprovedFiles recursively searches and removes unapproved file extensions
func removeUnapprovedFiles(root string, extensions []string) {
    filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        // If there's an error accessing the path, skip it
        if err != nil {
            return nil
        }
        // Skip special or hidden directories like /proc, /sys, /dev, etc. to avoid errors
        if info.IsDir() {
            skipDirs := []string{"/proc", "/sys", "/dev", "/run", "/boot", "/root"}
            for _, skipDir := range skipDirs {
                if path == skipDir {
                    return filepath.SkipDir
                }
            }
        } else {
            // Check file extension
            for _, ext := range extensions {
                if strings.HasSuffix(strings.ToLower(info.Name()), ext) {
                    fmt.Printf("Removing unapproved file: %s\n", path)
                    os.Remove(path)
                    break
                }
            }
        }
        return nil
    })
}

// disablePacketForwarding sets ip_forward=0 in /etc/sysctl.conf
func disablePacketForwarding() {
    fmt.Println("Ensuring no packet forwarding...")
    sysctlConfig := "/etc/sysctl.conf"
    forwardingRules := []string{
        "net.ipv4.ip_forward=0",
        "net.ipv6.conf.all.forwarding=0",
    }

    file, err := os.OpenFile(sysctlConfig, os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        fmt.Printf("Error opening %s: %v\n", sysctlConfig, err)
        return
    }
    defer file.Close()

    for _, rule := range forwardingRules {
        if !verifyFileContent(sysctlConfig, rule) {
            file.WriteString(rule + "\n")
        }
    }
    runCommand("sysctl -p") // Apply changes
}

// ensurePackageUpdates updates packages from secure sources
func ensurePackageUpdates(cfg Config) {
    if !cfg.UpdatePackages {
        fmt.Println("Package updates disabled in config.")
        return
    }

    switch cfg.OS {
    case "ubuntu", "debian":
        fmt.Println("Updating packages with apt (Debian/Ubuntu style)...")
        runCommand("apt update -y")
        runCommand("apt upgrade -y") // Avoid full-upgrade or dist-upgrade to prevent removal of monitored pkgs
    case "centos", "fedora", "redhat":
        fmt.Println("Updating packages with dnf/yum (RedHat/CentOS style)...")
        runCommand("dnf -y update || yum -y update")
    default:
        fmt.Printf("Unknown OS: %s. Skipping package updates.\n", cfg.OS)
    }
}

// removeUnneededPackages removes suspicious or unneeded packages
func removeUnneededPackages(cfg Config) {
    for _, pkg := range cfg.RemovePackages {
        // We'll do a simple apt/dnf remove attempt
        fmt.Printf("Removing package: %s\n", pkg)

        switch cfg.OS {
        case "ubuntu", "debian":
            runCommand(fmt.Sprintf("apt remove --purge -y %s*", pkg))
        case "centos", "fedora", "redhat":
            runCommand(fmt.Sprintf("dnf remove -y %s || yum remove -y %s", pkg, pkg))
        default:
            fmt.Println("Unsupported OS for package removal.")
        }
    }
}

// ensureSudoersPermissions ensures /etc/sudoers is 440
func ensureSudoersPermissions(cfg Config) {
    if !cfg.CheckSudoersPermissions {
        return
    }

    sudoersFile := "/etc/sudoers"
    if !verifyPermissions(sudoersFile, "440") {
        fmt.Println("Setting /etc/sudoers permission to 440.")
        runCommand(fmt.Sprintf("chmod 440 %s", sudoersFile))
    } else {
        fmt.Println("/etc/sudoers already has secure permissions (440).")
    }
}

// ensureOnlyCoreServices checks active services and stops/disables ones not in the keep list
func ensureOnlyCoreServices(cfg Config) {
    // This is an example approach using `systemctl list-units` and filtering
    fmt.Println("Ensuring only core services are running...")
    output, err := runCommand("systemctl list-units --type=service --state=active --no-pager --no-legend")
    if err != nil {
        fmt.Println("Error listing services:", err)
        return
    }

    lines := strings.Split(output, "\n")
    for _, line := range lines {
        // Typical line format: "cron.service        loaded active running  Regular background program processing daemon"
        fields := strings.Fields(line)
        if len(fields) < 1 {
            continue
        }
        service := fields[0] // e.g. "cron.service"
        if !strings.HasSuffix(service, ".service") {
            continue
        }
        base := strings.TrimSuffix(service, ".service")

        // Check if we should keep it
        keep := false
        for _, s := range cfg.ServicesToKeep {
            if base == s {
                keep = true
                break
            }
        }

        if !keep && base != "" {
            fmt.Printf("Service %s not in keep list. Stopping and disabling...\n", service)
            runCommand(fmt.Sprintf("systemctl stop %s", service))
            runCommand(fmt.Sprintf("systemctl disable %s", service))
        }
    }
}

// ------------------ Main Entry Point ------------------ //

func main() {
    // 1. Read the config file
    configFile := "config.json"
    data, err := ioutil.ReadFile(configFile)
    if err != nil {
        fmt.Printf("Error reading %s: %v\n", configFile, err)
        return
    }

    // 2. Parse JSON
    var cfg Config
    err = json.Unmarshal(data, &cfg)
    if err != nil {
        fmt.Printf("Error parsing JSON config: %v\n", err)
        return
    }

    // 3. Start Hardening Steps

    // A. Ensure authorized users
    ensureAuthorizedUsers(cfg)

    // B. Ensure firewall rules
    ensureFirewallRules(cfg)

    // C. Enforce secure password rules
    ensureSecurePasswordRules(cfg)

    // D. Remove unapproved files
    if len(cfg.UnapprovedExtensions) > 0 {
        fmt.Println("Removing unapproved files from system...")
        removeUnapprovedFiles("/", cfg.UnapprovedExtensions)
    }

    // E. Disable packet forwarding if requested
    if cfg.DisablePacketForwarding {
        disablePacketForwarding()
    }

    // F. Ensure only core services are running
    ensureOnlyCoreServices(cfg)

    // G. Update packages if configured
    ensurePackageUpdates(cfg)

    // H. Remove unneeded packages
    removeUnneededPackages(cfg)

    // I. Check /etc/sudoers permissions
    ensureSudoersPermissions(cfg)

    fmt.Println("System hardening script completed.")
}
