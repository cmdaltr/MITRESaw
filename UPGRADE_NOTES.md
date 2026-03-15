# MITRESaw Upgrade Notes - STIX/TAXII Integration

## Overview

This version of MITRESaw has been modernized with the following major improvements:

### 🚀 Key Enhancements

1. **STIX 2.1 Data Integration**
   - Replaced Excel/CSV file downloads with direct STIX data from MITRE's TAXII server
   - Uses `mitreattack-python` library (v3.0+) for native STIX object handling
   - Automatic version detection from TAXII server

2. **Multi-threading Support**
   - Parallel processing of techniques across threat groups
   - Configurable worker threads (default: 10)
   - Significant performance improvement for large datasets

3. **Automatic Version Management**
   - Auto-fetches latest MITRE ATT&CK version from TAXII server
   - No manual version updates required
   - Warns if hardcoded version differs from latest

4. **Improved Data Handling**
   - Native STIX object processing (no more regex parsing of CSV files)
   - Better error handling and logging
   - Cleaner data structures

## Installation

### Requirements

```bash
pip install -r requirements.txt
```

### New Dependencies

- `mitreattack-python>=3.0.0` - Official MITRE ATT&CK Python library
- `stix2>=3.0.0` - STIX 2.1 object handling
- `taxii2-client>=2.3.0` - TAXII server communication

## Usage

All arguments are now optional named flags with sensible defaults:

```bash
./MITRESaw.py [options]
```

### Examples

```bash
# Default export - all groups, Enterprise framework
./MITRESaw.py -d

# Quiet mode with default export
./MITRESaw.py -d -q

# Filter by platform and group
./MITRESaw.py -p Windows -g APT29

# Export as JSON instead of CSV
./MITRESaw.py -g APT29 -x json

# Generate queries for specific groups
./MITRESaw.py -p Windows -g APT29,Lazarus_Group -Q

# Filter by industry with navigation layers
./MITRESaw.py -t financial -n
```

## What Changed

### Architecture Changes

**Before:**
- Downloaded Excel files from MITRE website
- Converted to CSV and parsed with regex
- Sequential processing of techniques
- Manual version checking via web scraping

**After:**
- Direct STIX data retrieval from TAXII server
- Native STIX object handling
- Parallel processing with ThreadPoolExecutor
- Automatic version detection from STIX metadata

### Performance Improvements

- **Multi-threading**: Up to 10x faster technique processing (depends on number of groups/techniques)
- **No Excel parsing**: Eliminates pandas/openpyxl overhead
- **STIX caching**: Local caching for faster subsequent runs
- **Parallel HTTP requests**: Navigation layer downloads parallelized

### Data Quality

- **More accurate**: Direct from authoritative STIX source
- **Real-time**: Always uses latest data from TAXII server
- **Type-safe**: STIX objects provide structured data
- **Better relationships**: Native STIX relationship handling

## Compatibility

### CLI Changes

The CLI has been refactored from positional to named arguments:

| Old | New | Notes |
|-----|-----|-------|
| `Enterprise` (positional) | `-f Enterprise` | Defaults to Enterprise |
| `Windows` (positional) | `-p Windows` | Defaults to `.` (all) |
| `mining,tech` (positional) | `-t mining,tech` | Defaults to `.` (all) |
| `APT29` (positional) | `-g APT29` | Defaults to `.` (all) |
| `-p` / `--preset` | `-d` / `--default` | Renamed |
| `-t` / `--truncate` | `-r` / `--truncate` | Short flag changed |
| `-q` / `--queries` | `-Q` / `--queries` | Short flag changed |
| N/A | `-q` / `--quiet` | New: suppress per-identifier output |
| N/A | `-x` / `--export` | New: csv, json, xml export formats |
| `-a` hides art | `-a` shows art | Inverted: art hidden by default |

### Data Source Changes

- STIX data is now downloaded from GitHub mitre/cti and cached in `stix_data/`
- Data sources are resolved via the ATT&CK v16.1 detection strategy chain
- The `--default` (`-d`) preset exports to `./YYYY-MM-DD/mitre_procedures.csv`

## Performance Tuning

### Adjust Worker Threads

Edit `main.py` line 426 to change thread count:

```python
# Default: 10 workers
group_techniques_data, group_info_data, all_techniques_data = get_group_techniques_parallel(
    attack_data, groups, platforms, max_workers=10  # Adjust this number
)
```

**Recommendations:**
- 10 workers: Good balance for most systems
- 20 workers: High-performance systems with fast internet
- 5 workers: Limited bandwidth or older systems

## Troubleshooting

### Connection Issues

If you see "Unable to connect to the Internet":
- Check firewall settings for HTTPS access to `cti-taxii.mitre.org`
- Verify internet connectivity
- Try disabling VPN temporarily

### Timeout Errors

If TAXII queries timeout:
- Reduce worker threads
- Check network latency
- Ensure stable internet connection

### Version Warnings

If you see version mismatch warnings:
- The tool will automatically use the latest version
- Update `attack_version` in `MITRESaw.py` line 81 to match latest
- This is informational only and doesn't affect functionality

## Technical Details

### STIX Data Flow

1. **Connection**: Connect to MITRE TAXII server at `cti-taxii.mitre.org`
2. **Collection**: Select appropriate collection (Enterprise/Mobile/ICS)
3. **Query**: Fetch groups, techniques, and relationships
4. **Processing**: Extract relevant data with parallel workers
5. **Output**: Generate reports and navigator layers

### Thread Safety

The implementation uses:
- `ThreadPoolExecutor` for managed thread pool
- Immutable STIX objects (thread-safe by design)
- Thread-local results aggregation
- Exception isolation per thread

## Log Source Mapping Enhancements

### Expanded Detection Coverage

New log source mappings have been added across both generic (ATT&CK data source) and bespoke (environment-specific) layers:

**Generic mappings** (mapped to ATT&CK data sources):
- `Sysmon: 22` and `DNS Server Logs` for DNS-related data sources
- `Proxy logs` for network traffic content and connection creation
- `Firewall EventLog: 2003;2004;2005;2006` for firewall data sources
- `Terminal Services EventLog: 1149` for logon session creation
- `AppLocker EventLog: 8003;8004;8006;8007` for file and process monitoring
- `Defender EventLog: 1006;1007;1116;1117` for process access and creation
- `BITS EventLog: 59;60;16403` and `PrintService EventLog: 316;808;842` for service creation
- `*nix /var/log/audit/audit.log` and `*nix /var/log/syslog` for user account authentication

**Bespoke mappings** (technique and platform-based):
- `DNS logs` for DNS tunnelling and domain generation techniques
- `RDP logs` for RDP lateral movement
- `Proxy logs` for proxy and web-based techniques
- `IDS/IPS logs` for network scanning and intrusion detection
- `VPN logs` for VPN and remote access techniques
- `WAF logs` for web application attacks and brute force techniques
- `AWS GuardDuty` and `Azure Defender` for cloud platform threat detection

### Bespoke Log Source Categories

Bespoke log sources are now grouped into meaningful categories:
- **EDR-based**: `EDR (file logging)`, `EDR (process logging)`, `EDR (registry logging)`, `EDR (command logging)`, `EDR (network logging)`
- **Service-specific**: `Event logs`, `Email logs`, `MFA logs`, `DNS logs`, `RDP logs`, `Proxy logs`, `IDS/IPS logs`, `VPN logs`, `WAF logs`
- **Cloud**: `Azure logs`, `Azure Defender`, `AWS CloudTrail logs`, `AWS GuardDuty`

### New `detectable_via` Column

A `detectable_via` column has been added to CSV outputs, containing the log sources that can detect each technique as an array (e.g. `['EDR (process logging)', 'Event logs']`). This column is included in the `-d` default export preset.

### CVE Intelligence Enrichment

CVE identifiers are enriched with actionable intelligence from NVD and CISA KEV:
- Affected product and version information
- Exploit indicator strings for detection
- Public exploit/PoC references
- CISA Known Exploited Vulnerability (KEV) status

## Future Enhancements

Potential improvements for future versions:

- [ ] Async/await for even better performance
- [ ] Local STIX database caching
- [ ] Real-time TAXII subscriptions
- [ ] Custom STIX relationship queries
- [ ] Extended STIX object support (campaigns, tools, etc.)

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review MITRE ATT&CK documentation
3. Check `mitreattack-python` documentation

## Credits

- Original MITRESaw by [original author]
- STIX/TAXII integration update: 2025
- MITRE ATT&CK framework: https://attack.mitre.org
- mitreattack-python: https://github.com/mitre-attack/mitreattack-python
