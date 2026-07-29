#!/usr/bin/env python3
"""
KMS Cleanup and Audit Tool
Audits, disables, or schedules deletion of KMS keys within a specified GCP project.
Supports targeting specific regions and displays equivalent gcloud commands.
"""

import sys
import subprocess
import json
import argparse
from google.oauth2.credentials import Credentials
from googleapiclient import discovery
from tabulate import tabulate

def get_gcloud_token():
    try:
        token = subprocess.check_output(["gcloud", "auth", "print-access-token"], text=True).strip()
        return token
    except Exception as e:
        print(f"Error: Failed to retrieve active credentials from gcloud: {e}", file=sys.stderr)
        print("Please ensure you are authenticated by running: gcloud auth login", file=sys.stderr)
        sys.exit(1)

def get_active_gcloud_project():
    try:
        project = subprocess.check_output(["gcloud", "config", "get-value", "project"], text=True).strip()
        return project
    except Exception:
        return "proj-dev-1"

def parse_duration(duration_str):
    """Converts a duration string like '2592000s' or '86400s' into days (float)."""
    if not duration_str:
        return 24.0 / 24.0  # default KMS duration is 24h
    if duration_str.endswith('s'):
        seconds = int(duration_str[:-1])
        return seconds / 86400.0
    return 1.0

def audit_kms_keys(service, project_id, target_locations=None):
    print(f"\nAuditing KMS keys in project: '{project_id}'...")
    if target_locations:
        print(f"Filtering by region/location(s): {', '.join(target_locations)}")
    
    locations_client = service.projects().locations()
    keyrings_client = service.projects().locations().keyRings()
    keys_client = service.projects().locations().keyRings().cryptoKeys()
    versions_client = service.projects().locations().keyRings().cryptoKeys().cryptoKeyVersions()
    
    all_keys = []
    
    try:
        # 1. List locations
        locations_res = locations_client.list(name=f"projects/{project_id}").execute()
        locations = locations_res.get('locations', [])
        
        # Check target location validity
        if target_locations:
            valid_location_ids = [l['locationId'] for l in locations]
            invalid_locations = [loc for loc in target_locations if loc not in valid_location_ids]
            if invalid_locations:
                print(f"Error: Location(s) {invalid_locations} are not valid for project '{project_id}'.", file=sys.stderr)
                print(f"Valid locations include: {', '.join(valid_location_ids[:10])}...", file=sys.stderr)
                sys.exit(1)
            locations = [l for l in locations if l['locationId'] in target_locations]
            
        total_locs = len(locations)
        print(f"Scanning {total_locs} region(s)...")
        
        for idx, loc in enumerate(locations, 1):
            loc_name = loc['name']
            loc_id = loc['locationId']
            
            # Print real-time progress update
            print(f"\r[{idx}/{total_locs}] Scanning region: {loc_id}...", end="", flush=True)
            
            loc_keys_count = 0
            
            # 2. List KeyRings in this location
            kr_req = keyrings_client.list(parent=loc_name)
            while kr_req:
                kr_res = kr_req.execute()
                keyrings = kr_res.get('keyRings', [])
                
                for kr in keyrings:
                    kr_name = kr['name']
                    
                    # 3. List CryptoKeys in this KeyRing
                    keys_req = keys_client.list(parent=kr_name)
                    while keys_req:
                        keys_res = keys_req.execute()
                        keys = keys_res.get('cryptoKeys', [])
                        
                        for key in keys:
                            key_name = key['name']
                            purpose = key.get('purpose', 'UNKNOWN')
                            labels = key.get('labels', {})
                            labels_str = ", ".join([f"{k}:{v}" for k, v in labels.items()]) if labels else "None"
                            
                            # Parse deletion delay
                            duration_str = key.get('destroyScheduledDuration')
                            delay_days = parse_duration(duration_str)
                            
                            # 4. List CryptoKeyVersions for this CryptoKey to get state counts
                            versions_req = versions_client.list(parent=key_name)
                            version_states = {}
                            versions_list = []
                            
                            while versions_req:
                                versions_res = versions_req.execute()
                                versions = versions_res.get('cryptoKeyVersions', [])
                                
                                for v in versions:
                                    v_name = v['name']
                                    v_state = v.get('state', 'UNKNOWN')
                                    version_states[v_state] = version_states.get(v_state, 0) + 1
                                    versions_list.append({
                                        'name': v_name,
                                        'state': v_state
                                    })
                                
                                versions_req = versions_client.list_next(versions_req, versions_res)
                            
                            state_counts_str = ", ".join([f"{state}({count})" for state, count in version_states.items()])
                            
                            all_keys.append({
                                'name': key_name,
                                'location': loc_id,
                                'key_ring': kr_name.split('/')[-1],
                                'key_id': key_name.split('/')[-1],
                                'purpose': purpose,
                                'labels': labels_str,
                                'delay_days': delay_days,
                                'state_counts': state_counts_str or "No versions",
                                'versions': versions_list
                            })
                            loc_keys_count += 1
                            
                        keys_req = keys_client.list_next(keys_req, keys_res)
                
                kr_req = keyrings_client.list_next(kr_req, kr_res)
                
            # If keys were found in this region, print a line showing discovery
            if loc_keys_count > 0:
                print(f"\r[{idx}/{total_locs}] Region: {loc_id} - Discovered {loc_keys_count} key(s)")
                
        # Clear the last progress line
        print("\r" + " " * 60 + "\rScan complete!")
                
    except Exception as e:
        print(f"\nError during KMS audit: {e}", file=sys.stderr)
        sys.exit(1)
        
    return all_keys

def generate_gcloud_commands(action_type, project_id, key_info):
    """
    action_type: 'disable', 'destroy', 'both', or 'delete'
    """
    commands = []
    parts = key_info['name'].split('/')
    location_id = parts[3]
    keyring_id = parts[5]
    key_id = parts[7]
    
    if action_type == 'delete':
        non_deletable = []
        for v in key_info['versions']:
            v_name = v['name']
            v_state = v['state']
            v_id = v_name.split('/')[-1]
            
            if v_state in ['DESTROYED', 'IMPORT_FAILED', 'GENERATION_FAILED']:
                commands.append(f"gcloud kms keys versions delete {v_id} --key={key_id} --keyring={keyring_id} --location={location_id} --project={project_id}")
            else:
                non_deletable.append(v)
        
        # If there are no versions remaining that cannot be deleted, generate the key deletion command
        if not non_deletable:
            commands.append(f"gcloud kms keys delete {key_id} --keyring={keyring_id} --location={location_id} --project={project_id}")
    else:
        for v in key_info['versions']:
            v_name = v['name']
            v_state = v['state']
            v_id = v_name.split('/')[-1]
            
            if action_type in ['disable', 'both'] and v_state == 'ENABLED':
                commands.append(f"gcloud kms keys versions disable {v_id} --key={key_id} --keyring={keyring_id} --location={location_id} --project={project_id}")
            
            if action_type in ['destroy', 'both'] and v_state in ['ENABLED', 'DISABLED']:
                commands.append(f"gcloud kms keys versions destroy {v_id} --key={key_id} --keyring={keyring_id} --location={location_id} --project={project_id}")
            
    return commands

def disable_key_versions(service, key_info):
    print(f"\nDisabling active versions for key: {key_info['key_id']}")
    versions_client = service.projects().locations().keyRings().cryptoKeys().cryptoKeyVersions()
    
    modified_count = 0
    for v in key_info['versions']:
        if v['state'] == 'ENABLED':
            v_name = v['name']
            short_v_name = v_name.split('/')[-1]
            try:
                print(f"  -> Disabling version {short_v_name}...")
                versions_client.patch(
                    name=v_name,
                    updateMask="state",
                    body={"state": "DISABLED"}
                ).execute()
                print(f"     [SUCCESS] Version {short_v_name} is now DISABLED.")
                # update state locally for subsequent actions in the same run
                v['state'] = 'DISABLED'
                modified_count += 1
            except Exception as e:
                print(f"     [ERROR] Failed to disable version {short_v_name}: {e}")
    
    if modified_count == 0:
        print("  (No versions were in ENABLED state)")

def destroy_key_versions(service, key_info):
    print(f"\nScheduling destruction for active versions of key: {key_info['key_id']}")
    versions_client = service.projects().locations().keyRings().cryptoKeys().cryptoKeyVersions()
    
    modified_count = 0
    for v in key_info['versions']:
        if v['state'] in ['ENABLED', 'DISABLED']:
            v_name = v['name']
            short_v_name = v_name.split('/')[-1]
            try:
                print(f"  -> Scheduling destruction for version {short_v_name}...")
                versions_client.destroy(
                    name=v_name,
                    body={}
                ).execute()
                print(f"     [SUCCESS] Version {short_v_name} scheduled for destruction. (Will be permanently deleted in {key_info['delay_days']:.1f} days)")
                v['state'] = 'DESTROY_SCHEDULED'
                modified_count += 1
            except Exception as e:
                print(f"     [ERROR] Failed to schedule destruction for version {short_v_name}: {e}")
                
    if modified_count == 0:
        print("  (No versions were in ENABLED or DISABLED state)")

def permanently_delete_key_and_versions(service, key_info):
    print(f"\nProcessing permanent deletion for key: {key_info['key_id']}")
    versions_client = service.projects().locations().keyRings().cryptoKeys().cryptoKeyVersions()
    keys_client = service.projects().locations().keyRings().cryptoKeys()
    
    key_name = key_info['name']
    
    deleted_versions_count = 0
    non_deletable_versions_count = 0
    
    for v in key_info['versions']:
        v_name = v['name']
        v_state = v['state']
        short_v_name = v_name.split('/')[-1]
        
        if v_state in ['DESTROYED', 'IMPORT_FAILED', 'GENERATION_FAILED']:
            try:
                print(f"  -> Permanently deleting version {short_v_name}...")
                versions_client.delete(name=v_name).execute()
                print(f"     [SUCCESS] Version {short_v_name} has been permanently deleted.")
                deleted_versions_count += 1
            except Exception as e:
                print(f"     [ERROR] Failed to delete version {short_v_name}: {e}")
                non_deletable_versions_count += 1
        else:
            print(f"  -> Version {short_v_name} is in state '{v_state}' and cannot be deleted yet (requires DESTROYED, IMPORT_FAILED, or GENERATION_FAILED).")
            non_deletable_versions_count += 1
            
    if non_deletable_versions_count == 0:
        try:
            print(f"  -> All versions deleted. Deleting parent CryptoKey {key_info['key_id']}...")
            keys_client.delete(name=key_name).execute()
            print(f"     [SUCCESS] CryptoKey {key_info['key_id']} has been permanently deleted.")
        except Exception as e:
            print(f"     [ERROR] Failed to delete parent CryptoKey {key_info['key_id']}: {e}")
    else:
        print(f"  -> Cannot delete parent CryptoKey {key_info['key_id']} because {non_deletable_versions_count} version(s) remain.")

def parse_arguments():
    parser = argparse.ArgumentParser(description="GCP KMS Cleanup and Audit Tool")
    parser.add_argument("-p", "--project", help="GCP Project ID to audit")
    parser.add_argument("-r", "--regions", help="Comma-separated list of target regions/locations (default: all)")
    parser.add_argument("-a", "--action", choices=["disable", "destroy", "both", "delete"], help="Action to perform: disable, destroy, both, delete")
    parser.add_argument("-k", "--keys", help="Target keys: 'all', or comma-separated list of index numbers (e.g. '1,3')")
    parser.add_argument("-m", "--mode", choices=["dry-run", "execute", "both"], help="Execution mode: dry-run, execute, both")
    parser.add_argument("-y", "--confirm", action="store_true", help="Auto-confirm execution (bypasses the confirmation prompt)")
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    # 1. Authentication
    token = get_gcloud_token()
    credentials = Credentials(token)
    service = discovery.build('cloudkms', 'v1', credentials=credentials)
    
    # Determine if running in CLI mode (any argument provided except config flags or just basic launch)
    # We can check if args has any defined values
    is_cli_mode = bool(args.project or args.regions or args.action or args.keys or args.mode or args.confirm)
    
    if is_cli_mode:
        project_id = args.project
        if not project_id:
            project_id = get_active_gcloud_project()
        
        target_locations = [x.strip() for x in args.regions.split(',') if x.strip()] if args.regions else None
    else:
        print("====================================================")
        print("             KMS Key Audit & Cleanup Tool           ")
        print("====================================================")
        # 2. Get target project ID and target region
        default_project = get_active_gcloud_project()
        project_id = input(f"Enter the GCP Project ID to audit [{default_project}]: ").strip()
        if not project_id:
            project_id = default_project
            
        target_locations_input = input("Enter specific region/location(s) (comma-separated, e.g. us-east4, global) or press Enter for ALL: ").strip()
        if target_locations_input:
            target_locations = [x.strip() for x in target_locations_input.split(',') if x.strip()]
        else:
            target_locations = None
        
    # 3. Perform Audit
    keys = audit_kms_keys(service, project_id, target_locations)
    
    if not keys:
        print("\nNo KMS keys found in this project matching the criteria.")
        return
        
    # Region summary
    region_summary = {}
    for k in keys:
        loc = k['location']
        region_summary[loc] = region_summary.get(loc, 0) + 1
        
    if not is_cli_mode:
        print(f"\n================ AUDIT SUMMARY ================")
        print(f"Found {len(keys)} KMS key(s) in {len(region_summary)} region(s):")
        for region, count in sorted(region_summary.items()):
            print(f" - {region}: {count} key(s)")
        print(f"================================================")
        
        input("\nPress Enter to view the full details table...")
    
    # 4. Display Audit Table
    headers = ["#", "Location", "Key Ring", "Key ID", "Purpose", "Versions State", "Labels", "Del. Delay"]
    table_data = []
    for idx, k in enumerate(keys, 1):
        table_data.append([
            idx,
            k['location'],
            k['key_ring'],
            k['key_id'],
            k['purpose'],
            k['state_counts'],
            k['labels'],
            f"{k['delay_days']:.1f} days"
        ])
    
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    # 5. Prompt for Action
    if is_cli_mode:
        action_choice_str = args.action
        if not action_choice_str:
            print("Error: --action or -a argument is required in CLI mode.", file=sys.stderr)
            sys.exit(1)
        action_map = {"disable": "1", "destroy": "2", "both": "3", "delete": "4"}
        action_choice = action_map[action_choice_str]
    else:
        print("\nSelect an action to perform:")
        print("1. Disable (Expire) enabled key versions")
        print("2. Schedule Destruction of active key versions")
        print("3. Disable & Schedule Destruction of active key versions")
        print("4. Permanently Delete destroyed/failed versions and parent keys")
        print("5. Exit")
        
        action_choice = input("Enter choice (1/2/3/4/5): ").strip()
        if action_choice not in ['1', '2', '3', '4']:
            print("Exiting tool. No actions performed.")
            return
        
    # 6. Select Keys
    if is_cli_mode:
        selection_input = args.keys or "all"
    else:
        print("\nSelect the keys to target:")
        print("- Type 'all' to select all keys")
        print("- Or enter a comma-separated list of numbers (e.g. 1,3,4)")
        selection_input = input("Enter selection: ").strip()
    
    target_keys = []
    if selection_input.lower() == 'all':
        target_keys = keys
    else:
        try:
            indices = [int(x.strip()) for x in selection_input.split(',')]
            for idx in indices:
                if 1 <= idx <= len(keys):
                    target_keys.append(keys[idx - 1])
                else:
                    print(f"Skipping invalid index: {idx}")
        except ValueError:
            print("Invalid input format. Exiting.")
            return
            
    if not target_keys:
        print("No keys selected. Exiting.")
        return
        
    action_type = "disable" if action_choice == '1' else ("destroy" if action_choice == '2' else ("both" if action_choice == '3' else "delete"))
    action_name = {
        '1': "DISABLE",
        '2': "SCHEDULE DESTRUCTION",
        '3': "DISABLE & SCHEDULE DESTRUCTION",
        '4': "PERMANENT DELETE"
    }[action_choice]
    
    print(f"\nYou have selected to {action_name} versions for the following {len(target_keys)} key(s):")
    for tk in target_keys:
        print(f" - {tk['key_id']} (in KeyRing {tk['key_ring']}, Location {tk['location']})")
        
    # Ask execution mode: print commands or execute directly
    if is_cli_mode:
        mode_choice_str = args.mode or "dry-run"
        mode_map = {"dry-run": "1", "execute": "2", "both": "3"}
        mode_choice = mode_map[mode_choice_str]
    else:
        print("\nSelect execution mode:")
        print("1. Print equivalent gcloud CLI commands (Dry-run / Learn)")
        print("2. Execute actions directly via this script")
        print("3. Both (Print commands first, then execute)")
        mode_choice = input("Enter choice (1/2/3) [1]: ").strip()
        if not mode_choice:
            mode_choice = '1'
        
    # Generate commands
    all_commands = []
    for tk in target_keys:
        cmds = generate_gcloud_commands(action_type, project_id, tk)
        all_commands.extend(cmds)
        
    if mode_choice in ['1', '3']:
        print(f"\n================ EQUIVALENT GCLOUD COMMANDS ================")
        if not all_commands:
            print("No matching versions eligible for this action.")
        for cmd in all_commands:
            print(cmd)
        print(f"=============================================================")
        if action_type in ["destroy", "both"] and all_commands:
            print("\nNOTE: Executing these gcloud commands will schedule deletion.")
            print("Key versions will be permanently destroyed after their safety delays (indicated in the Del. Delay column).")
        elif action_type == "delete" and all_commands:
            print("\nNOTE: Executing these gcloud commands will immediately and permanently delete the targeted versions/keys.")
            print("This action is completely IRREVERSIBLE.")
            
    if mode_choice in ['2', '3']:
        # Confirmation prompt
        if is_cli_mode and args.confirm:
            confirm = "confirm"
        else:
            confirm = input(f"\nAre you absolutely sure you want to execute {action_name} on GCP directly? (type 'confirm' to execute): ").strip()
            
        if confirm.lower() != 'confirm':
            print("Execution cancelled.")
            return
            
        for tk in target_keys:
            if action_choice == '1':
                disable_key_versions(service, tk)
            elif action_choice == '2':
                destroy_key_versions(service, tk)
            elif action_choice == '3':
                disable_key_versions(service, tk)
                destroy_key_versions(service, tk)
            elif action_choice == '4':
                permanently_delete_key_and_versions(service, tk)
                
        print("\nDirect execution completed.")
    else:
        print("\nDry-run completed. No changes were made on GCP.")

if __name__ == "__main__":
    main()
