package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Config holds the configuration from config.json
type Config struct {
	OSType             string              `json:"osType"`
	FirewallRules      map[string]string   `json:"firewallRules"`
	AuthorizedUsers    []string            `json:"authorizedUsers"`
	UnapprovedFiles    []string            `json:"unapprovedFiles"`
	CoreServices       []string            `json:"coreServices"`
	PasswordRules      []string            `json:"passwordRules"`
	ForwardingRules    []string            `json:"forwardingRules"`
	SudoersPermissions string              `json:"sudoersPermissions"`
}

// Global config variable
var config Config

// LoadConfig reads the configuration from config.json
func loadConfig() error {
	file, err := os.ReadFile("config.json")
	if err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	err = json.Unmarshal(file, &config)
	if err != nil {
		return fmt.Errorf("error parsing config file: %v", err)
	}

	return nil
}

// runCommand executes a shell command and returns its output and error
func runCommand(command string) (string, error) {
	cmd := exec.Command("sh", "-c", command)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// verifyPermissions checks if a file has the expected permissions
func verifyPermissions(filePath, expectedPermissions string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}
	mode := info.Mode().Perm()
	return fmt.Sprintf("%o", mode) == expectedPermissions
}

// verifyFileContent checks if a file contains the expected content
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

// verifyUserInGroup checks if a user is in a specific group
func verifyUserInGroup(username, group string) bool {
	output, err := runCommand(f"getent group {group}")
	if err != nil {
		return false
	}
	return strings.Contains(output, username)
}

// verifyShellForUser checks if a user has the expected shell
func verifyShellForUser(username, expectedShell string) bool {
	output, err := runCommand(f"getent passwd {username}")
	if err != nil {
		return false
	}
	return strings.Contains(output, expectedShell)
}

// removeUnapprovedFiles removes files with unapproved extensions
func removeUnapprovedFiles(directory string, extensions []string) {
	filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			for _, ext := range extensions {
				if strings.HasSuffix(info.Name(), ext) {
					fmt.Printf("Removing unapproved file: %s\n", path)
					os.Remove(path)
				}
			}
		}
		return nil
	})
}

// ensureFirewallRules ensures proper firewall rules are set
func ensureFirewallRules() {
	fmt.Println("Ensuring firewall rules...")
	for service, rule := range config.FirewallRules {
		fmt.Printf("Allowing %s (%s)\n", service, rule)
		runCommand(f"ufw allow {rule}")
	}
	runCommand("ufw deny in from any to any") // Deny all other incoming traffic
	runCommand("ufw enable")
}

// ensureSecurePasswordRules ensures secure password rules in /etc/pam.d/common-password
func ensureSecurePasswordRules() {
	fmt.Println("Ensuring secure password rules...")
	filePath := "/etc/pam.d/common-password"
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	for _, rule := range config.PasswordRules {
		if !verifyFileContent(filePath, rule) {
			file.WriteString(rule + "\n")
		}
	}
}

// ensureNoPacketForwarding ensures no packet forwarding is enabled
func ensureNoPacketForwarding() {
	fmt.Println("Ensuring no packet forwarding...")
	sysctlConfig := "/etc/sysctl.conf"
	file, err := os.OpenFile(sysctlConfig, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	for _, rule := range config.ForwardingRules {
		if !verifyFileContent(sysctlConfig, rule) {
			file.WriteString(rule + "\n")
		}
	}
	runCommand("sysctl -p") // Apply changes
}

// ensureOnlyCoreServices ensures only core services are running
func ensureOnlyCoreServices() {
	fmt.Println("Ensuring only core services are running...")
	output, _ := runCommand("systemctl list-units --type=service --state=active")
	fmt.Println("Active services:\n", output)
	// Add logic to disable non-core services
}

// ensurePackageUpdates ensures all packages are updated from secure sources
func ensurePackageUpdates() {
	fmt.Println("Ensuring package updates...")
	switch config.OSType {
	case "ubuntu":
		runCommand("sudo apt update")
		runCommand("sudo apt upgrade -y")
	case "centos":
		runCommand("sudo yum update -y")
	default:
		fmt.Println("Unsupported OS for package updates.")
	}
}

// ensureSudoersSecure ensures the sudoers file is secure
func ensureSudoersSecure() {
	fmt.Println("Ensuring sudoers file is secure...")
	sudoersFile := "/etc/sudoers"
	if !verifyPermissions(sudoersFile, config.SudoersPermissions) {
		runCommand(f"sudo chmod {config.SudoersPermissions} {sudoersFile}")
	}
}

// ensureNoGamesOrCheats ensures no games or cheats are installed
func ensureNoGamesOrCheats() {
	fmt.Println("Ensuring no games or cheats are installed...")
	output, _ := runCommand("dpkg -l")
	if strings.Contains(output, "game") || strings.Contains(output, "cheat") {
		fmt.Println("Found games or cheats. Removing...")
		runCommand("sudo apt remove --purge game* cheat*")
	}
}

// main function
func main() {
	// Load configuration from config.json
	err := loadConfig()
	if err != nil {
		fmt.Println(err)
		return
	}

	// 1. Ensure authorized users are on the machine
	fmt.Println("Ensuring authorized users...")
	for _, user := range config.AuthorizedUsers {
		if !verifyUserInGroup(user, "sudo") {
			runCommand(f"sudo usermod -aG sudo {user}")
		}
	}

	// 2. Ensure firewall is running with proper rules
	ensureFirewallRules()

	// 3. Ensure secure password rules
	ensureSecurePasswordRules()

	// 4. Ensure no weird files are on the machine
	fmt.Println("Removing unapproved files...")
	removeUnapprovedFiles("/", config.UnapprovedFiles)

	// 5. Ensure no packet forwarding
	ensureNoPacketForwarding()

	// 6. Ensure only core services are running
	ensureOnlyCoreServices()

	// 7. Ensure package updates
	ensurePackageUpdates()

	// 8. Ensure sudoers file is secure
	ensureSudoersSecure()

	// 9. Ensure no games or cheats are installed
	ensureNoGamesOrCheats()

	fmt.Println("Script execution completed.")
}
