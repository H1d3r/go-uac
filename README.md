# go-uac

A UAC bypass technique using Windows directory parsing quirks and DLL hijacking with support for multiple auto-elevate binaries.

## Demo 
![demo4](https://github.com/user-attachments/assets/f1b2c0bb-d64f-45c0-939e-549f80b6e06d)

## How It Works

This tool exploits Windows' inconsistent handling of directory names with trailing spaces:

1. Creates a directory `C:\windows ` (with trailing space)
2. Copies an auto-elevate binary and a malicious DLL to the fake system32 directory
3. Patches the DLL with shellcode that executes at DLL load
4. When the binary launches, it loads the malicious DLL instead of the legitimate one
5. Since the binary is auto-elevate, it runs with elevated privileges

The key insight is that `CreateProcess` and file APIs handle trailing spaces differently, allowing this directory spoofing attack.

## Supported Methods

### Method 1: perfmon.exe + atl.dll (Default)
- Uses Performance Monitor (`perfmon.exe`)
- Hijacks `atl.dll` (Active Template Library)
- Smaller DLL size (~98KB)

### Method 2: ComputerDefaults.exe + propsys.dll
- Uses Computer Defaults (`ComputerDefaults.exe`) 
- Hijacks `propsys.dll` (Property System)
- Larger DLL size (~982KB) but alternative injection target

## Usage

### Prerequisites

- Windows 10/11
- Go 1.19+
- Administrative privileges disabled (to test the bypass)

### Build and Run

```bash
go mod tidy
go build -o uac-bypass.exe cmd/main.go
```

### Default Method (perfmon.exe)
```bash
./uac-bypass.exe
```

### Choose Specific Method
```bash
# Use perfmon.exe with atl.dll
./uac-bypass.exe -method perfmon

# Use ComputerDefaults.exe with propsys.dll  
./uac-bypass.exe -method computerdefaults
```
### Command Line Options

- `-method`: Choose bypass method
  - `perfmon` - Uses perfmon.exe with atl.dll (default)
  - `computerdefaults` - Uses ComputerDefaults.exe with propsys.dll

### What Happens

1. Tool creates the spoofed directory structure
2. Embeds and patches the malicious DLL using enhanced code cave detection
3. Launches the chosen auto-elevate binary from the fake location
4. Checks if the process is running elevated
5. Displays shellcode execution (message box)

## Enhanced Features

### Code Cave Detection
This tool includes code cave detection with multiple strategies:

- **Multiple Section Support**: Searches `.text`, `.rdata`, `.data`, `.rsrc` and other sections
- **Detection Strategies**:
  - Consecutive zeros (original method)
  - Sparse zeros (80%+ zero content)
  - Padding patterns (0x00, 0xCC, 0x90)
  - End padding detection
- **Detailed Diagnostics**: Shows which sections and strategies are tried
- **Fallback Logic**: Automatically tries alternative sections if preferred ones fail

## Files

- `cmd/main.go` - Main bypass logic with dual method support
- `cmd/atl.dll` - Embedded ATL DLL (patched at runtime) (THESE ARE STOCK DLLS AT FIRST)
- `cmd/propsys.dll` - Embedded Property System DLL (patched at runtime)
- `go.mod` - Go module dependencies

## Detection

This technique can be detected by:
- Monitoring for directories with trailing spaces in system paths
- File integrity monitoring on system binaries
- Process monitoring for unexpected DLL loads
- Monitoring auto-elevate binary execution from non-standard locations

## Credits

I found this technique from [@wietze](https://x.com/wietze?s=21&t=D56Bma43bmGkkf0oTt4tug) but another person may have discovered it.

## Disclaimer

This tool is for educational and authorized penetration testing purposes only. Do not use against systems you do not own or have explicit permission to test. 
