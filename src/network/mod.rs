use crate::models::InterfaceInfo;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// Fetches an IP Helper table into an 8-byte-aligned buffer, retrying when
/// the table grows between the size query and the data call (previously a
/// grown table was silently dropped). The buffer is `Vec<u64>` so the table
/// structs are never read through an under-aligned `Vec<u8>` cast.
unsafe fn query_tcp_table(af: u32, class: TCP_TABLE_CLASS) -> Option<Vec<u64>> {
    let mut size = 0u32;
    let _ = GetExtendedTcpTable(null_mut(), &mut size, 0, af, class, 0);
    if size == 0 {
        return None;
    }
    for _ in 0..3 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let mut got = size;
        let ret = GetExtendedTcpTable(buf.as_mut_ptr() as *mut _, &mut got, 0, af, class, 0);
        if ret == 0 {
            return Some(buf);
        }
        if ret != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        size = got;
    }
    None
}

unsafe fn query_udp_table(af: u32, class: UDP_TABLE_CLASS) -> Option<Vec<u64>> {
    let mut size = 0u32;
    let _ = GetExtendedUdpTable(null_mut(), &mut size, 0, af, class, 0);
    if size == 0 {
        return None;
    }
    for _ in 0..3 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let mut got = size;
        let ret = GetExtendedUdpTable(buf.as_mut_ptr() as *mut _, &mut got, 0, af, class, 0);
        if ret == 0 {
            return Some(buf);
        }
        if ret != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        size = got;
    }
    None
}

/// PIDs that are actively exchanging traffic: owners of ESTABLISHED TCP
/// connections (v4 + v6) and of UDP endpoints. LISTEN/idle TCP sockets do
/// not count, so "Active Internet" in the UI reflects real traffic.
pub fn get_active_network_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();
    unsafe {
        if let Some(buf) = query_tcp_table(AF_INET as u32, TCP_TABLE_OWNER_PID_ALL) {
            let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
            let num_entries = (*table).dwNumEntries;
            let rows = std::slice::from_raw_parts((*table).table.as_ptr(), num_entries as usize);
            for row in rows {
                if row.dwOwningPid > 4 && row.dwState as i32 == MIB_TCP_STATE_ESTAB {
                    pids.insert(row.dwOwningPid);
                }
            }
        }

        if let Some(buf) = query_tcp_table(AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL) {
            let table = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
            let num_entries = (*table).dwNumEntries;
            let rows = std::slice::from_raw_parts((*table).table.as_ptr(), num_entries as usize);
            for row in rows {
                if row.dwOwningPid > 4 && row.dwState as i32 == MIB_TCP_STATE_ESTAB {
                    pids.insert(row.dwOwningPid);
                }
            }
        }

        if let Some(buf) = query_udp_table(AF_INET as u32, UDP_TABLE_OWNER_PID) {
            let table = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
            let num_entries = (*table).dwNumEntries;
            let rows = std::slice::from_raw_parts((*table).table.as_ptr(), num_entries as usize);
            for row in rows {
                if row.dwOwningPid > 4 {
                    pids.insert(row.dwOwningPid);
                }
            }
        }

        if let Some(buf) = query_udp_table(AF_INET6 as u32, UDP_TABLE_OWNER_PID) {
            let table = buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
            let num_entries = (*table).dwNumEntries;
            let rows = std::slice::from_raw_parts((*table).table.as_ptr(), num_entries as usize);
            for row in rows {
                if row.dwOwningPid > 4 {
                    pids.insert(row.dwOwningPid);
                }
            }
        }
    }
    pids
}

/// Terminates existing IPv4 TCP connections owned by the given PIDs
/// (SetTcpEntry with DELETE_TCB). IPv6 connections cannot be terminated
/// this way — SetTcpEntry only accepts the IPv4 MIB_TCPROW layout (the old
/// code cast a MIB_TCP6ROW to it, which never worked) — so IPv6 is covered
/// by the firewall rule for new connections, not by teardown.
pub fn terminate_tcp_connections_for_pids(target_pids: &HashSet<u32>) {
    if target_pids.is_empty() {
        return;
    }
    unsafe {
        if let Some(buf) = query_tcp_table(AF_INET as u32, TCP_TABLE_OWNER_PID_ALL) {
            let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
            let num_entries = (*table).dwNumEntries;
            let rows = std::slice::from_raw_parts((*table).table.as_ptr(), num_entries as usize);
            for row in rows {
                if target_pids.contains(&row.dwOwningPid) {
                    let mut tcp_row: MIB_TCPROW_LH = std::mem::zeroed();
                    tcp_row.Anonymous.dwState = MIB_TCP_STATE_DELETE_TCB as u32;
                    tcp_row.dwLocalAddr = row.dwLocalAddr;
                    tcp_row.dwLocalPort = row.dwLocalPort;
                    tcp_row.dwRemoteAddr = row.dwRemoteAddr;
                    tcp_row.dwRemotePort = row.dwRemotePort;
                    let _ = SetTcpEntry(&tcp_row);
                }
            }
        }
    }
}

pub fn interfaces() -> Result<Vec<InterfaceInfo>, String> {
    let mut buf_len: u32 = 16384;
    let mut buf: Vec<u8> = vec![0; buf_len as usize];

    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut ret = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            flags,
            null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len,
        )
    };

    if ret == 111 {
        // ERROR_BUFFER_OVERFLOW
        buf.resize(buf_len as usize, 0);
        ret = unsafe {
            GetAdaptersAddresses(
                AF_INET as u32,
                flags,
                null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_len,
            )
        };
    }

    if ret != 0 {
        return Err(format!(
            "GetAdaptersAddresses failed with error code {}",
            ret
        ));
    }

    let mut out = Vec::new();
    let mut curr = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

    while !curr.is_null() {
        let adapter = unsafe { &*curr };

        // Friendly name
        let name = if !adapter.FriendlyName.is_null() {
            let mut len = 0;
            while unsafe { *adapter.FriendlyName.add(len) } != 0 {
                len += 1;
            }
            let slice = unsafe { std::slice::from_raw_parts(adapter.FriendlyName, len) };
            String::from_utf16_lossy(slice)
        } else {
            "Unknown Adapter".into()
        };

        // Description
        let description = if !adapter.Description.is_null() {
            let mut len = 0;
            while unsafe { *adapter.Description.add(len) } != 0 {
                len += 1;
            }
            let slice = unsafe { std::slice::from_raw_parts(adapter.Description, len) };
            String::from_utf16_lossy(slice)
        } else {
            String::new()
        };

        // Adapter GUID string ("{...}") — the stable identity of the adapter.
        let adapter_id = if !adapter.AdapterName.is_null() {
            let mut bytes = Vec::new();
            let mut p = adapter.AdapterName;
            unsafe {
                while *p != 0 {
                    bytes.push(*p);
                    p = p.add(1);
                }
            }
            String::from_utf8_lossy(&bytes).to_string()
        } else {
            String::new()
        };

        let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        let is_up = adapter.OperStatus == 1; // IfOperStatusUp
        let status = if is_up { "Up" } else { "Down" }.to_string();

        // Extract IPv4 address: prefer a real address over an APIPA
        // (169.254.x.x) self-assigned one; an adapter whose only address is
        // APIPA has no working network and is marked as such by the caller.
        let mut candidates: Vec<Ipv4Addr> = Vec::new();
        let mut unicast = adapter.FirstUnicastAddress;
        while !unicast.is_null() {
            let u = unsafe { &*unicast };
            let sa = u.Address.lpSockaddr;
            if !sa.is_null() && unsafe { (*sa).sa_family } == AF_INET {
                let sin = unsafe { &*(sa as *const SOCKADDR_IN) };
                let bytes = unsafe { sin.sin_addr.S_un.S_un_b };
                let ip = Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4);
                if !ip.is_loopback() && !ip.is_unspecified() {
                    candidates.push(ip);
                }
            }
            unicast = u.Next;
        }
        let ipv4 = candidates
            .iter()
            .find(|ip| !ip.is_link_local())
            .or_else(|| candidates.first())
            .map(|ip| ip.to_string());

        // Extract Gateway
        let mut gateway: Option<String> = None;
        let mut gw = adapter.FirstGatewayAddress;
        while !gw.is_null() {
            let g = unsafe { &*gw };
            let sa = g.Address.lpSockaddr;
            if !sa.is_null() && unsafe { (*sa).sa_family } == AF_INET {
                let sin = unsafe { &*(sa as *const SOCKADDR_IN) };
                let bytes = unsafe { sin.sin_addr.S_un.S_un_b };
                let ip = Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4);
                if !ip.is_unspecified() {
                    gateway = Some(ip.to_string());
                    break;
                }
            }
            gw = g.Next;
        }

        // Check if virtual / tunnel adapter
        // IF_TYPE_SOFTWARE_LOOPBACK = 24, IF_TYPE_TUNNEL = 131, IF_TYPE_PPP = 23
        let virtual_adapter = adapter.IfType == 24 || adapter.IfType == 131 || adapter.IfType == 23;

        // Skip loopback adapters
        if adapter.IfType != 24 {
            out.push(InterfaceInfo {
                name,
                index,
                adapter_id,
                status,
                description,
                ipv4,
                gateway,
                virtual_adapter,
            });
        }

        curr = adapter.Next;
    }

    out.sort_by_key(|a| a.index);
    Ok(out)
}

/// True for APIPA self-assigned addresses (169.254.0.0/16): the adapter has
/// no DHCP lease and cannot actually reach the internet.
pub fn is_apipa_ipv4(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>()
        .map(|a| a.is_link_local())
        .unwrap_or(false)
}

pub fn is_likely_vpn(i: &InterfaceInfo) -> bool {
    let s = format!("{} {}", i.name, i.description).to_ascii_lowercase();
    let substring_keywords = [
        "wireguard",
        "wintun",
        "openvpn",
        "tailscale",
        "warp",
        "vpn",
        "fortinet",
        "cisco",
        "hamachi",
        "zerotier",
        "v2ray",
        "xray",
        "sing-box",
        "nekoray",
        "clash",
        "hiddify",
        // Virtual / non-physical adapters that are never the "direct" uplink:
        "hyper-v",
        "vethernet",
        "vmware",
        "virtualbox",
        "virtual",
        "bluetooth",
        "loopback",
        "pseudo",
    ];
    if substring_keywords.iter().any(|k| s.contains(k)) {
        return true;
    }
    // "tap"/"tun" match as whole tokens only — as substrings they also hit
    // unrelated words in legitimate adapter names/descriptions.
    let token_hit = s
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|t| t == "tap" || t == "tun");
    token_hit || i.virtual_adapter
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, description: &str, virtual_adapter: bool) -> InterfaceInfo {
        InterfaceInfo {
            name: name.into(),
            index: 1,
            adapter_id: "{00000000-0000-0000-0000-000000000000}".into(),
            status: "Up".into(),
            description: description.into(),
            ipv4: None,
            gateway: None,
            virtual_adapter,
        }
    }

    #[test]
    fn vpn_heuristic_detects_tunnels() {
        assert!(is_likely_vpn(&iface(
            "WireGuard Tunnel",
            "Wintun Userspace Tunnel",
            false
        )));
        assert!(is_likely_vpn(&iface(
            "Ethernet",
            "TAP-Windows Adapter V9",
            false
        )));
        assert!(is_likely_vpn(&iface("Local Area Connection", "", true)));
    }

    #[test]
    fn vpn_heuristic_keeps_physical_adapters() {
        assert!(!is_likely_vpn(&iface(
            "Wi-Fi",
            "Intel(R) Wi-Fi 6 AX201",
            false
        )));
        assert!(!is_likely_vpn(&iface(
            "Ethernet",
            "Realtek PCIe GbE",
            false
        )));
        assert!(!is_likely_vpn(&iface(
            "Ethernet 2",
            "Realtek USB GbE Family Controller",
            false
        )));
    }

    #[test]
    fn vpn_heuristic_flags_virtual_adapters() {
        assert!(is_likely_vpn(&iface(
            "vEthernet (WSL)",
            "Hyper-V Virtual Ethernet Adapter",
            false
        )));
        assert!(is_likely_vpn(&iface(
            "VMware Network Adapter VMnet8",
            "VMware Virtual Ethernet Adapter",
            false
        )));
        assert!(is_likely_vpn(&iface(
            "Bluetooth Network Connection",
            "Bluetooth Device (Personal Area Network)",
            false
        )));
    }

    #[test]
    fn apipa_detection() {
        assert!(is_apipa_ipv4("169.254.10.20"));
        assert!(!is_apipa_ipv4("192.168.1.10"));
        assert!(!is_apipa_ipv4("not-an-ip"));
    }
}
