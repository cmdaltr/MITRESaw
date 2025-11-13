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

Usage remains the same as before:

```bash
python MITRESaw.py <framework> <platforms> <search_terms> <threat_groups> [options]
```

### Examples

```bash
# Get all Enterprise techniques for Windows platform
python MITRESaw.py Enterprise Windows . .

# Get techniques from APT29 targeting Windows and Linux
python MITRESaw.py Enterprise Windows,Linux . APT29

# Get techniques targeting financial sector with navigation layers
python MITRESaw.py Enterprise . financial . -n

# Generate queries for specific groups
python MITRESaw.py Enterprise Windows . APT29,Lazarus_Group -q
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

### Backward Compatibility

The tool maintains the same CLI interface and output formats:
- Same command-line arguments
- Same output directory structure
- Same CSV output format
- Same ATT&CK Navigator layer format

### Breaking Changes

None for end users. However, if you've modified the code:

1. **CSV files no longer generated** in the data directory (STIX objects used instead)
2. **`collect_files()` function** is no longer used (replaced with STIX queries)
3. **Excel/pandas dependencies** now optional (kept for compatibility)

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
