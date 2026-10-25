# VMware Workstation 16.2.5 VMDK Mount Restoration

A self-contained, in-place binary patching utility for the **VMware 16.2.5 installer**. It transplants the mount driver package from 16.1.2 (the last community-verified working version) to restore broken VMDK host mounting in 16.2.x.

---

## Project Overview

Since VMware Workstation 16.2.0, VMDK mounting has been broken when mounting virtual disks in read/write mode, as documented in multiple community reports[^1] [^2].

Until now, the only known community workaround was manually copying an old `vstor2.sys` from version 16.1.2 into `System32\drivers`. That approach is flawed:
* It omitted the security catalog (`vstor2.cat`) and INF file (`vstor2.inf`), leaving the driver unsigned (WHQL issue).
* Because the driver file is locked by the system while Windows is running, replacing it required rebooting into WinPE.

**This project solves the problem at the installation source.** It modifies the official 16.2.5 installation package directly, injecting the complete, WHQL-signed 16.1.2 driver bundle before VMware is ever installed.

**16.2.5** (the final release of the 16.x branch) is the only supported version of this patcher. In Workstation 17.0+, VMware completely removed the feature and its UI entry altogether, making driver injection futile on 17.x.

[^1]: [Broadcom Community: Cannot mount vmdk to host](https://community.broadcom.com/vmware-cloud-foundation/communities/community-home/digestviewer/viewthread?GroupId=7171&MessageKey=63e8a97e-08ca-4d16-b877-03447ea67a00&CommunityKey=fb707ac3-9412-4fad-b7af-018f5da56d9f)
[^2]: [Broadcom Community: Recent 16.x versions can't mount a writeable NTFS Disk](https://community.broadcom.com/vmware-cloud-foundation/communities/community-home/digestviewer/viewthread?GroupId=7171&MessageKey=934a7e37-8c6f-4533-81fa-e3210d54bf78&CommunityKey=fb707ac3-9412-4fad-b7af-018f5da56d9f)

---

## Usage

The script is a self-contained binary patcher that performs **minimal in-place** binary patching of the installer itself. For how minimal the patching process is, refer to [this doc](HOW-THE-MINIMAL-PATCH.md).

1. Download the [patcher script](VMware_16.2.5_vstor2_Patcher.bat), and run it:
   * You can drag-n-drop the installer `VMware-workstation-full-16.2.5-20904516.exe` on it.
   * Or you can just simply double-click to run it, it will ask you to locate the file with an `open file dialog`.
   * Alternatively, the extracted `.msi` inside the `.exe` is supported.
2. The patcher will verify the input with SHA256, create an automatic `.bak` backup, then patch the file in-place.
3. Run the resulting patched installer to install VMware Workstation 16.2.5 with working VMDK mounting.

### Important Deployment Notes

#### 1. Cleanly Uninstall Existing 16.2.x First
Windows Installer strictly enforces the **"Highest Version Wins"** rule for versioned files:
* Restored driver (16.1.2): `6.2.0.511`
* Broken driver (16.2.5): `6.2.0.563` *(16.2.0-16.2.4 have versions in between)*

If any version of VMware 16.2.x is already installed on the machine, Windows Installer will silently skip replacing the newer driver on disk during an in-place upgrade.  
**You must completely uninstall any existing 16.2.x installation (and possibly reboot to ensure the driver files are gone) before running the patched installer.**

#### 2. Prefer the Patched Full Installer (`.exe`) Over Naked `.msi`
Running a raw `.msi` directly by double-clicking it runs the initial setup UI under a standard user token, UAC elevation only occurs at the final UI stage when clicking "Install". It appears that VMware's licensing and machine initialization actions are run during the unelevated context, consequently fail silently, permanently breaking license key registration.  
**Patching and running the official `.exe` installer is strongly recommended**, as it requests full administrator privileges on startup, which avoids this issue entirely.

## Source And References

The patcher verifies the input file against known official hashes before making any changes. The output is bit-for-bit deterministic.

| Variant | original SHA256 Checksum | Expected Patched SHA256 Checksum | 
| :--- | :--- | :--- |
| **VMware 16.2.5 Full Installer (`.exe`)** | `380b0fa8a0f37ade496573cdc2ad922d3985bc83664f94431a9e513444b6c377` | `0c075660067998bf19b868783082adb7b863aaa22b17ea95b382be515d92ba20` |
| **Standalone VMware 16.2.5 MSI (`.msi`)** | `a21847666ab2f8d2f81782d60e16e057709d87cd827ceab10906f3616e29d62d` | `382b6a2ebc0c62082685e8081ff5becfbe79b543d45ecfe718c8acd3850d330c` |

The python script output by the agent to reveal some low-level structure can be found in `src/`.