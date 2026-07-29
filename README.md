# GCP KMS Key Audit & Cleanup Tool

A lightweight, interactive Python CLI tool to audit KMS keys in a Google Cloud project, allowing you to easily disable (expire) or schedule the destruction of key versions.

> [!CAUTION]
> **HIGH RISK OPERATION**: Disabling or destroying KMS keys can cause immediate, catastrophic service disruptions and permanent data loss if the keys are actively protecting data resources (such as Google Compute Engine disks, Cloud SQL databases, Google Cloud Storage buckets, or GCBDR recovery points).
>
> Always perform a **Dry-Run (Mode 1)** first to verify target keys and versions before executing any changes on GCP.


## Features

- **Project-wide or Region-specific Audit**: Scans all locations or filters specifically by a region of your choice (e.g. `us-east4`, `global`).
- **Interactive Region Summary**: Shows how many keys were found and in which regions before showing the detailed breakdown.
- **Dry-Run & Learn Mode**: Option to output the equivalent `gcloud` CLI commands for your chosen actions, helping you learn the exact terminal syntax to disable or delete keys version-by-version.
- **Detailed Visibility**: Displays a structured table showing the purpose, labels, version states, and specific destruction delay of each key.
- **Selective Actions**: Perform actions on all discovered keys or select specific keys by their index.
- **Two Cleanup Modes**:
  1. **Disable (Expire)**: Disables all enabled versions of selected keys immediately, preventing any cryptographic operations.
  2. **Schedule Destruction**: Schedules active versions for deletion. Key versions are permanently deleted after their configured safety delay (e.g., 24 hours or 30 days).

---

## Prerequisites

1. **Google Cloud SDK**:
   Make sure you have the `gcloud` CLI installed and authenticated to your account:
   ```bash
   gcloud auth login
   ```

2. **Python Dependencies**:
   This script requires Python 3 and the following Python packages:
   ```bash
   pip install google-api-python-client google-auth tabulate
   ```

---

## Usage

1. Run the script:
   ```bash
   python3 kms_cleanup.py
   ```

2. **Enter Project ID**: Enter the target project ID (e.g., `argo-svc-dev-1`). If you press Enter, it defaults to the active project set in your `gcloud` CLI context.
3. **Specify Region(s)**: Press Enter to scan all regions, or type one or more specific locations/regions separated by commas (e.g., `australia-southeast1, australia-southeast2`) to target.
4. **Review Summary & Details**: Check the counts summary, press Enter, and inspect the table showing all found keys.
5. **Choose Action**:
   - `1`: Disable (Expire) enabled key versions.
   - `2`: Schedule destruction of active key versions.
   - `3`: Disable & Schedule destruction of active key versions.
   - `4`: Exit.
6. **Select Target Keys**:
   - Type `all` to target all keys.
   - Or enter comma-separated numbers (e.g. `1, 3, 5`).
7. **Select Execution Mode**:
   - `1`: Print equivalent gcloud CLI commands (Dry-run / Learn).
   - `2`: Execute actions directly via this script.
   - `3`: Both (Print commands first, then execute).
8. **Confirm**: (Only if executing) Type `confirm` to execute the selected action.

---

## Deletion Safety & Cleanup Duration

In Google Cloud KMS, **CryptoKeys cannot be deleted directly**. Instead, their individual **CryptoKeyVersions** must be scheduled for destruction.

- **Disabling (Expiration)**: **Immediate**. The state of the key version changes to `DISABLED` and it can no longer be used for encryption/decryption immediately. This action is fully reversible.
- **Permanent Destruction**: **Delayed**. When scheduled for destruction, the key version changes to `DESTROY_SCHEDULED` state.
  - **How long does it take?** It depends on the key's `destroyScheduledDuration` configuration. The default for newly created keys is **24 hours**, but it can be configured up to **120 days**.
  - In `argo-svc-dev-1`, many keys (e.g. `kek` keys) are configured with a safety delay of `2592000s` (**30 days**).
  - During this safety period, the keys can be recovered using the KMS Restore API.
  - After the safety period passes, the key material is **permanently and irreversibly destroyed** (state becomes `DESTROYED`).
