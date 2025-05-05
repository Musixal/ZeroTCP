package ZeroTCP

import (
	"fmt"
	"os/exec"
)

// runIptablesWithSudo executes the iptables command with sudo
func runIptablesWithSudo(args []string) error {
	// Prepend "sudo" to the command
	fullCommand := append([]string{"iptables"}, args...)
	cmd := exec.Command("sudo", fullCommand...)

	// Execute the command and capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute iptables command: %v\noutput: %s", err, output)
	}

	fmt.Printf("Command executed successfully: %s\n", output)
	return nil
}
