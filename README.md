# go-uac

A UAC bypass technique using Windows directory parsing quirks and DLL hijacking.

## How It Works

This tool exploits Windows' inconsistent handling of directory names with trailing spaces:

1. Creates a directory `C:\windows ` (with trailing space)
2. Copies `perfmon.exe` and a malicious `atl.dll` to the fake system32 directory
3. Patches `atl.dll` with shellcode that executes at DLL load
4. When `perfmon.exe` launches, it loads the malicious `atl.dll` instead of the legitimate one
5. Since `perfmon.exe` is an auto-elevate binary, it runs with elevated privileges

The key insight is that `CreateProcess` and file APIs handle trailing spaces differently, allowing this directory spoofing attack.

## Usage

### Prerequisites

- Windows 10/11
- Go 1.19+
- Administrative privileges disabled (to test the bypass)

### Build and Run

```bash
go mod tidy
go build -o uac-bypass.exe cmd/main.go
./uac-bypass.exe
```

### What Happens

1. Tool creates the spoofed directory structure
2. Embeds and patches the malicious DLL
3. Launches perfmon.exe from the fake location
4. Checks if perfmon.exe is running elevated
5. Displays shellcode execution (message box)

## Files

- `cmd/main.go` - Main bypass logic
- `atl.dll` - Embedded legitimate ATL DLL (patched at runtime)
- `go.mod` - Go module dependencies

## Detection

This technique can be detected by:
- Monitoring for directories with trailing spaces in system paths
- File integrity monitoring on system binaries
- Process monitoring for unexpected DLL loads

## Credits

I found this technique from [@wietze](https://x.com/wietze?s=21&t=D56Bma43bmGkkf0oTt4tug) but another person may have discovered it.

## Disclaimer

This tool is for educational and authorized penetration testing purposes only. Do not use against systems you do not own or have explicit permission to test. 