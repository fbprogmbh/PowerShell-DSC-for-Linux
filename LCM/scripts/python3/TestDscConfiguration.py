#!/usr/bin/env python3
import fileinput
import sys
import subprocess
from OmsConfigHostHelpers import write_omsconfig_host_telemetry, write_omsconfig_host_switch_event, write_omsconfig_host_log, stop_old_host_instances
import warnings
with warnings.catch_warnings():
    warnings.filterwarnings("ignore",category=DeprecationWarning)
import importlib.util
from os.path              import dirname, isfile, join, realpath
from time                 import sleep
from fcntl                import flock, LOCK_EX, LOCK_UN, LOCK_NB
from sys                  import argv
import os
import re
import hashlib
from pathlib import Path
import json

def parse_mof(file_path):
    mof_data = Path(file_path).read_text(encoding='utf-8')
    hash_to_resource_id = {}  # Dictionary to store MD5 hashes as keys and ResourceIDs as values
    
    resource_blocks = re.split(r'(?=instance of MSFT_)', mof_data)[1:]  # Skip first empty split
    
    for block in resource_blocks:
        if 'MSFT_nxScriptResource' in block:
            key_match = re.search(r'GetScript\s*=\s*"""(.*?)"""|GetScript\s*=\s*"(.*?)"', block, re.DOTALL)
        elif 'MSFT_nxPackageResource' in block:
            key_match = re.search(r'(?<=\s)Name\s*=\s*"(.*?)"', block)
        elif 'MSFT_nxServiceResource' in block:
            key_match = re.search(r'(?<=\s)Name\s*=\s*"(.*?)"', block)
        elif 'MSFT_nxFileResource' in block:
            key_match = re.search(r'(?<=\s)DestinationPath\s*=\s*"(.*?)"', block)
        else:
            continue  # Skip if neither resource type

        if key_match:
            key_value = key_match.group(1) or key_match.group(2)
            key_value = key_value.replace('\n', r'\n')  # Normalize line breaks
            
            resource_id_match = re.search(r'ResourceID\s*=\s*"(.*?)"', block)
            if resource_id_match:
                resource_id = resource_id_match.group(1)
                
                md5_hash = hashlib.md5(key_value.encode('utf-8')).hexdigest()
                
                hash_to_resource_id[md5_hash] = resource_id
    
    return hash_to_resource_id

def process_report(report_path, hash_to_resource_id):
    resources_in_desired_state = []  # List to store ResourceIDs with state 0
    resources_in_not_desired_state = []  # List to store ResourceIDs with state 1
    
    # Open and read the report file
    with open(report_path, 'r') as report_file:
        for line in report_file:
            line = line.strip()
            
            if line:
                md5_hash, state = line.split(':')
                resource_id = hash_to_resource_id.get(md5_hash)
                
                if resource_id:
                    if state == '0':
                        resources_in_desired_state.append(resource_id)
                    elif state == '1':
                        resources_in_not_desired_state.append(resource_id)

    return {
        "ResourcesInDesiredState": resources_in_desired_state,
        "ResourcesInNotDesiredState": resources_in_not_desired_state
    }


pathToCurrentScript = realpath(__file__)
pathToCommonScriptsFolder = dirname(pathToCurrentScript)

DSCLogPath = join(pathToCommonScriptsFolder, 'nxDSCLog.py')
spec = importlib.util.spec_from_file_location('nxDSCLog', DSCLogPath)
nxDSCLog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nxDSCLog)
LG = nxDSCLog.DSCLog

helperLibPath = join(pathToCommonScriptsFolder, 'helperlib.py')
spec = importlib.util.spec_from_file_location('helperlib', helperLibPath)
helperlib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helperlib)

omicli_path = join(helperlib.CONFIG_BINDIR, 'omicli')
dsc_host_base_path = helperlib.DSC_HOST_BASE_PATH
dsc_host_path = join(dsc_host_base_path, 'bin/dsc_host')
dsc_host_output_path = join(dsc_host_base_path, 'output')
dsc_host_lock_path = join(dsc_host_base_path, 'dsc_host_lock')
dsc_host_switch_path = join(dsc_host_base_path, 'dsc_host_ready')

LG().Log("DEBUG", "Starting script logic for " + argv[0]+ " runing with python " + str(sys.version_info))

if ("omsconfig" in helperlib.DSC_SCRIPT_PATH):
    write_omsconfig_host_switch_event(pathToCurrentScript, isfile(dsc_host_switch_path))

if ("omsconfig" in helperlib.DSC_SCRIPT_PATH) and (isfile(dsc_host_switch_path)):
    use_omsconfig_host = True
else:
    use_omsconfig_host = False

parameters = []
if use_omsconfig_host:
    parameters.append(dsc_host_path)
    parameters.append(dsc_host_output_path)
    parameters.append("TestConfiguration")
else:
    parameters.append(omicli_path)
    parameters.append("iv")
    parameters.append("root/Microsoft/DesiredStateConfiguration")
    parameters.append("{")
    parameters.append("MSFT_DSCLocalConfigurationManager")
    parameters.append("}")
    parameters.append("TestConfiguration")

stdout = ''
stderr = ''

report_path = "/var/opt/omi/run/report"

if os.path.exists(report_path):
        os.remove(report_path)
        
if use_omsconfig_host:
    if isfile(dsc_host_lock_path):
        try:
            dschostlock_filehandle = None
            stop_old_host_instances(dsc_host_lock_path)

            # Open the dsc host lock file. This also creates a file if it does not exist
            dschostlock_filehandle = open(dsc_host_lock_path, 'w')
            print("Opened the dsc host lock file at the path '" + dsc_host_lock_path + "'")
            
            dschostlock_acquired = False

            # Acquire dsc host file lock
            for retry in range(10):
                try:
                    flock(dschostlock_filehandle, LOCK_EX | LOCK_NB)
                    write_omsconfig_host_log('dsc_host lock file is acquired by : TestConfiguration', pathToCurrentScript)
                    dschostlock_acquired = True
                    break
                except IOError:
                    write_omsconfig_host_log('dsc_host lock file not acquired. retry (#' + str(retry) + ') after 60 seconds...', pathToCurrentScript)
                    sleep(60)

            if dschostlock_acquired:
                p = subprocess.Popen(parameters, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = p.communicate()
                exit_code = p.wait()
                stdout = stdout.decode() if isinstance(stdout, bytes) else stdout
                print(stdout)

                if (isinstance(exit_code, int) and exit_code > 0):
                    write_omsconfig_host_log('dsc_host failed with code = ' + str(exit_code), pathToCurrentScript)
                    exit(exit_code)
            else:
                print("dsc host lock already acuired by a different process")
        finally:
            if (dschostlock_filehandle):
                # Release dsc host file lock
                flock(dschostlock_filehandle, LOCK_UN)

                # Close dsc host lock file handle
                dschostlock_filehandle.close()
    else:
        write_omsconfig_host_log('dsc_host lock file does not exist. Skipping this operation until next consistency hits.', pathToCurrentScript, 'WARNING')
else:
        
    p = subprocess.Popen(parameters, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

stdout = stdout.decode() if isinstance(stdout, bytes) else stdout
stderr = stderr.decode() if isinstance(stderr, bytes) else stderr
print(stdout)
print(stderr)

LG().Log("DEBUG", "End of script logic for " +  argv[0] + " runing with python " + str(sys.version_info))

file_path = "/etc/opt/omi/conf/dsc/configuration/Current.mof"  # Replace with actual MOF file path

hash_to_resource_id  = parse_mof(file_path)
result_dict = process_report(report_path, hash_to_resource_id)

print(json.dumps(hash_to_resource_id, indent=4))
if os.path.exists(report_path):
        os.remove(report_path)
        
result_json = json.dumps(result_dict, indent=4)

print(result_json)
