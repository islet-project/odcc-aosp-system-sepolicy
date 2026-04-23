## How to Extend SELinux Policy for Arm CCA Realms in AOSP Microdroid and AVF

This policy tree has been extended to support the **Arm Confidential Compute Architecture** (CCA) in Microdroid running in a Realm VM using the **Android Virtualization Framework** (AVF). The goal is to enable Microdroid to host Confidential Computing Services (**CC Services**) written in Java or Kotlin using a standard Android API. The Microdroid environment has been extended to provide **CC Services** with Arm CCA remote attestation, provisioning of confidential data over a RA-TLS channel, and sealing key derivation functionality. The changes introduce new domains (`kvmtool`,
`microdroid_dhcp`, `avf_prop`) and extend existing ones (`virtualizationmanager`, `toolbox`,
`microdroid_manager`, `microdroid_payload`, `microdroid_app`) to cover the full lifecycle:
VM launch via lkvm, guest networking (DHCP/NTP), access to the Realm Services Interface (RSI) driver, confidential data
provisioning, and DEX payload execution under the Dalvik VM. The result is a fully enforcing SELinux policy
for the Microdroid and CC Services running in a Realm.

## SELinux Rules — Per Domain

### Domain: `kvmtool` (new)

**Context:** Host Android (Cuttlefish/QEMU). This is the `lkvm` process spawned by `virtualizationmanager`.

| Resource | Permissions | Reason |
|---|---|---|
| `vm_manager_device_type` (`/dev/kvm`) | `rw_file_perms` | kvmtool needs `/dev/kvm` to launch Realm VMs |
| `tun_device` (`/dev/net/tun`) | `{ read write ioctl }` (no `open`) | `vmnic` (root:vpn) creates the TAP interface and passes a ready fd via `SCM_RIGHTS`. kvmtool cannot open `/dev/tun` itself: it is `crw-rw---- system:vpn` and kvmtool runs as app UID (~10115). `open` is omitted — DAC would block it anyway. |
| `tun_device` ioctl | `TUNSETIFF TUNGETIFF TUNSETOFFLOAD TUNSETVNETHDRSZ` | Required to configure the TAP interface received via fd passing |
| `self:tcp_socket` | `{ create ioctl }` | virtio-net code in lkvm creates a dummy socket to query network interface state. Not used for data transfer. |
| `self:tcp_socket` ioctl | `SIOCGIFFLAGS SIOCGIFADDR` | Interface status queries via the dummy socket |
| `anon_inode` (`kvm-gmem`) | `write` | Guest memory for the VM via KVM — required to start the VM |
| `virtualizationservice_data_file`, `app_data_file`, etc. | `read getattr lock` | VM disk images, `instance.img` |
| fd from `virtualizationmanager` / `untrusted_app` | `use read write` | VM console, log pipes |

---

### Domain: `virtualizationmanager` — extensions

**Context:** Host Android.

| Resource / Rule | Reason |
|---|---|
| `domain_auto_trans(virtualizationmanager, kvmtool_exec, kvmtool)` | Forces transition to the `kvmtool` domain when lkvm is exec'd |
| `capability { dac_override dac_read_search }` | `derive_classpath` (enumerates APEX classpath at microdroid start) needs to traverse directories regardless of DAC ownership |
| `self:dir add_name`, `self:file create`, `proc:filesystem associate` | `derive_classpath` writes output via `/proc/self/fd` |
| `anon_inode write` | `kvm-gmem` — required by crosvm (not only kvmtool) |
| `system_data_root_file getattr` | Checking the `use_kvmtool()` flag (`/data/use_kvmtool` or property) |
| `app_data_file:dir search` | Locating microdroid config/disk images in `/data/app/...` |

---

### Domain: `avf_prop` (new property type)

**Context:** Host Android. Affects `property_contexts`, `shell`, `virtualizationmanager`.

| Rule | Reason |
|---|---|
| `system_internal_prop(avf_prop)` | Allows `shell` (adb) to `setprop persist.avf.kvmtool` and `persist.avf.realm`. Using `system_vendor_config_prop` would be wrong — it is blocked by a neverallow: `neverallow { domain -init -vendor_init } system_vendor_config_prop:...` |
| `get_prop(virtualizationmanager, avf_prop)` | `virtmgr` reads `persist.avf.kvmtool` (whether to use lkvm instead of crosvm) and `persist.avf.realm` (whether to launch a Realm VM) |
| `set_prop(shell, avf_prop)` | Allows control via `adb shell` (testing, feature enabling) |

---

### Domain: `microdroid_dhcp` (new)

**Context:** Guest VM (microdroid). DHCP scripts running inside the VM.

| Resource | Permissions | Reason |
|---|---|---|
| `netlink_route_socket` + `capability net_admin` | standard | Configure the network interface after receiving a DHCP lease |
| `shell_exec`, `system_file`, `toolbox_exec` | `execute` | The DHCP script calls additional tools (`ip`, `ifconfig`) |
| `kmsg_device` | `write` | Logging to the kernel ring buffer |

---

### Domain: `microdroid_manager` — extensions

**Context:** Guest VM.

| Resource | Permissions | Reason |
|---|---|---|
| `sysfs:dir/file` | `{ read open getattr }` | Reading serial numbers of block devices via `/sys/block/vdX/serial` (disk identification at VM boot) |
| `sysfs_net:dir` | `{ search read open }` | Detecting network interfaces in the VM (checking if network is available) |
| `capability chown` | — | Changing file ownership after writing to encryptedstore (microdroid_manager sets ownership for the payload) |
| `encryptedstore_file` | `{ read open getattr setattr }` | microdroid_manager reads files from encrypted storage after download (verification, handoff to payload) |
| `domain_auto_trans(microdroid_manager, system_file/toolbox_exec, toolbox)` | — | `ip`, `dhcp`, `sntp` launched by microdroid_manager transition to the `toolbox` domain (not staying in `microdroid_manager`). **Note:** in permissive mode they appear as `microdroid_manager` (`execute_no_trans` not enforced) — in enforcing mode they MUST transition to `toolbox`. |
| `udp_socket` + ioctl `0x8933` (`SIOCGIFNAME`) | `create ioctl` | microdroid_manager queries network interfaces directly |
| `netlink_route_socket` + `net_admin` | — | Routing configuration after DHCP (`ip route add`) |

---

### Domain: `toolbox` — extensions for DHCP/NTP

**Context:** Guest VM.

| Resource | Permissions | Reason |
|---|---|---|
| `udp_socket` | `create` | `sntp` (NTP sync) — sends UDP queries to the time server. **Important:** NTP must complete before attestation (TLS requires correct time). |
| `packet_socket` + `rawip_socket` | — | `dhcp` — the BOOTP/DISCOVER phase before the VM has an IP address requires a raw Ethernet socket for broadcast |
| `netlink_route_socket` + `net_admin` + `net_raw` | — | `dhcp` configures the interface after receiving a lease |
| `capability sys_time` | — | `sntp` sets the system clock after NTP synchronization |
| `sysfs_net` + `proc_net` | `read` | Reading network interface state |
| `udp_socket` ioctl | `SIOCSIFFLAGS SIOCSIFADDR SIOCSIFBRDADDR SIOCSIFNETMASK` | `ifconfig` — setting IP address, netmask, broadcast |
| `rawip_socket` ioctl | `SIOCGIFHWADDR SIOCADDRT` | `SIOCGIFHWADDR` = read MAC address; `SIOCADDRT` = add route table entry |

---

### Domain: `toolbox` — extensions for `ratls_get`

**Context:** Guest VM.

> `ratls_get` is a Rust binary labeled `system_file`.
> In **permissive** mode it appears as `microdroid_manager` (`execute_no_trans` not enforced).
> In **enforcing** mode it transitions to `toolbox` via `domain_auto_trans(microdroid_manager, system_file, toolbox)`.

| Resource | Permissions | Reason |
|---|---|---|
| `self:tcp_socket` | `{ create setopt connect name_connect getopt }` | `ratls_get` establishes an HTTPS/RA-TLS connection to the provisioning server using the `reqwest` Rust library to download confidential file |
| `port:tcp_socket name_connect` | TCP port | The provisioning server listens on a TCP port |
| `rsi_device:chr_file` | `{ read write open ioctl }` | `ratls_get` retrieves the Realm Attestation Token via RSI and embeds it in the TLS certificate (RA-TLS). An external Verifier verifies the attestation token to check if the CCA Platform and the Realm content are trustworthy  before issuing the confidential file. |
| `proc_overcommit_memory` | `r_file_perms` | `reqwest` reads `/proc/sys/vm/overcommit_memory` at initialization — standard Rust runtime behavior |
| `encryptedstore_file:dir` | `{ search write add_name }` | `ratls_get` creates a provisioned confidential file in the encrypted storage |
| `encryptedstore_file:file` | `{ create write open getattr }` | Writing the provisioned confidential file |

---

### Domain: `microdroid_payload`

**Context:** Guest VM. Payload process running inside microdroid.

| Resource | Permissions | Reason |
|---|---|---|
| `rsi_device:chr_file` | `rw_file_perms` | Access to the RSI driver. Microdroid Manager can call: `RSI_MEASUREMENT_EXTEND`, `RSI_ATTESTATION_TOKEN`, `RSI_MEASUREMENT_READ`. |
| `tcp_socket` + `udp_socket` | `create_socket_perms` | BertQA service communicates over the network (e.g. answering queries from the host via vsock/TCP) |

---

### Domain: `microdroid_app`

**Context:** Guest VM. Application code passed in and executed by microdroid_manager.

| Resource | Permissions | Reason |
|---|---|---|
| `default_prop:file` | `{ getattr map }` | Android bionic/ART reads basic system properties at initialization (e.g. `ro.debuggable`) |
| `dalvik_config_prop:file` | `{ read open getattr map }` | ART reads JIT/GC configuration: `dalvik.vm.heapsize`, `dalvik.vm.jitinitialsize`, etc. |
| `device_config_runtime_native_prop:file` | `{ read open getattr map }` | `device_config` feature flags for the ART runtime |
| `apex_info_file:file` | `{ getattr read open map }` | `/apex/apex-info-list.xml` — ART needs to know which APEXes are installed (library paths, versions) |
| `unlabeled:dir/file` | `{ search getattr }` | `system_zoneinfo_file` in microdroid is labeled `unlabeled` (label does not map in the simplified microdroid policy). Required for timezone data access by ART. |
| `tmpfs:file` | `{ write map read execute }` | JIT cache — ART compiles JIT code to an anonymous file (`memfd`) which is then mapped executable (`W^X` relaxed for JIT): `memfd_create()` + `mmap(PROT_EXEC)` |
| `tmpfs:dir` | `{ search read open getattr }` | General tmpfs access (`/dev`, `/tmp`) by ART runtime |
| `console_device:chr_file` | `append` | Payload stderr goes to the VM console (`hvc0`) |
| `self:anon_inode` (`userfaultfd`) | `{ create ioctl }` | ART Garbage Collector uses `userfaultfd` for concurrent GC (handling page faults in the background without stopping threads) |
