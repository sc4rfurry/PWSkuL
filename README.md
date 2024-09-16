```
                                                               .---. 
_________   _...._                          .                  |   | 
\        |.'      '-.         _     _     .'|                  |   | 
 \        .'```'.    '. /\    \\   //   .'  |                  |   | 
  \      |       \     \`\\  //\\ //   <    |                  |   | 
   |     |        |    |  \`//  \'/ _   |   | ____      _    _ |   | 
   |      \      /    .    \|   |/.' |  |   | \ .'     | '  / ||   | 
   |     |\`'-.-'   .'      '    .   | /|   |/  .     .' | .' ||   | 
   |     | '-....-'`           .'.'| |//|    /\  \    /  | /  ||   | 
  .'     '.                  .'.'.-'  / |   |  \  \  |   `'.  |'---' 
'-----------'                .'   \_.'  '    \  \  \ '   .'|  '/     
                                       '------'  '---'`-'  `--'      
```

# PWSkul // NetRecon Toolkit

[![License](https://img.shields.io/badge/license-MIT-neon.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-cyan.svg)](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.1)
[![Contributions](https://img.shields.io/badge/contributions-welcome-lime.svg)](CONTRIBUTING.md)

## // Table_of_Contents

- [Overview](#overview)
- [Key_Features](#key_features)
- [Getting_Started](#getting_started)
  - [Prerequisites](#prerequisites)
  - [Basic_Usage](#basic_usage)
  - [Parameters](#parameters)
- [Advanced_Usage](#advanced_usage)
- [Output_Formats](#output_formats)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## // Overview

**PWSkul** is a sophisticated PowerShell script engineered for comprehensive network reconnaissance. It empowers users to efficiently scan hosts within specified CIDR ranges, offering a versatile toolkit for network administrators and security professionals.

## // Key_Features

- **Multi-CIDR Scanning**: Analyze multiple network ranges simultaneously
- **Customizable Host Discovery**: Fine-tune ping attempts and timeout settings
- **Port Scanning**: Identify open ports on live hosts
- **DNS Resolution**: Retrieve DNS information for discovered hosts
- **Flexible Export Options**: Generate reports in CSV, JSON, or XML formats
- **Exclusion Capabilities**: Omit specific IP addresses or subnets from scans
- **TCP SYN Scanning**: Utilize stealthy SYN packets for host discovery
- **Network Interface Selection**: Choose specific interfaces for targeted scanning
- **Comprehensive Logging**: Maintain detailed records of scan activities

## // Getting_Started

### > Prerequisites

- PowerShell 5.1 or later

### > Basic_Usage

<!-- Reference to the Docs.html for more details -->
> **Note:** For more details and Docs, refer to the [Docs.html](Docs.html) file.

#

```powershell
.\scanner.ps1 -CIDR "192.168.1.0/24" -PingCount 2 -Timeout 500 -ShowAll
```

### > Parameters

| Param               | Function                                                | Default    |
|---------------------|----------------------------------------------------------|------------|
| `-CIDR`             | Target CIDR notation(s) (single or array)                |            |
| `-PingCount`        | Number of ping attempts per host                         | 1          |
| `-Timeout`          | Ping timeout in milliseconds                             | 1000       |
| `-ShowAll`          | Display results for all hosts                            | False      |
| `-ExportCSV`        | Path for CSV export                                      |            |
| `-HostThrottleLimit`| Max concurrent host scans                                | 100        |
| `-PortThrottleLimit`| Max concurrent port scans                                | 50         |
| `-ResolveDNS`       | Enable DNS resolution                                    | False      |
| `-Ports`            | List of ports to scan                                    |            |
| `-TopPorts`         | Number of top ports to scan (10, 20, 30, 40, 50)         |            |
| `-LogFile`          | Path to log file                                         | .\scan_log.txt |
| `-OutputFormat`     | Result format (CSV, JSON, XML)                           | CSV        |
| `-Exclude`          | IP addresses or subnets to exclude                       |            |
| `-UseTcpSyn`        | Use TCP SYN for host discovery                           | False      |
| `-NetworkInterface` | Specify network interface for scanning                   |            |
| `-Help`             | Display help information                                 |            |
| `-Detailed`         | Show detailed help                                       |            |

## // Advanced_Usage

### > Port_Scanning
```powershell
.\scanner.ps1 -CIDR "192.168.1.0/24" -PingCount 2 -Timeout 500 -ShowAll -Ports "80,443,3306"
```

### > Top_Ports_Scan
```powershell
.\scanner.ps1 -CIDR "192.168.1.0/24" -PingCount 2 -Timeout 500 -ShowAll -TopPorts 20
```

### > CSV_Export
```powershell
.\scanner.ps1 -CIDR "192.168.1.0/24" -PingCount 2 -Timeout 500 -ShowAll -ExportCSV "C:\loot\netmap.csv"
```

### > Subnet_Exclusion
```powershell
.\scanner.ps1 -CIDR "192.168.1.0/24" -PingCount 2 -Timeout 500 -ShowAll -Exclude "192.168.1.0/25"
```

### > TCP_SYN_Discovery
```powershell
.\scanner.ps1 -CIDR "192.168.1.0/24" -PingCount 2 -Timeout 500 -ShowAll -UseTcpSyn
```

### > Detailed_Help
```powershell
.\scanner.ps1 -Detailed
```

## // Output_Formats

PWSkul supports multiple output formats to suit various reporting needs:

- **CSV**: Comma-separated values for easy spreadsheet integration
- **JSON**: Structured data ideal for programmatic analysis
- **XML**: Extensible format for complex data representation

## // Contributing

We welcome contributions from the community! .

## // License

PWSkul is released under the MIT License. See the [LICENSE](LICENSE.md) file for full details.

## // Contact

For inquiries, support, or to report issues, please contact me at [akalucifr@protonmail.ch](mailto:akalucifr@protonmail.ch).

---

`PWSkul: Infiltrate. Analyze. Dominate.`
