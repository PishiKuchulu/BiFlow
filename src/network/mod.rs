use crate::models::InterfaceInfo;
use std::net::Ipv4Addr;
use std::ptr::null_mut;
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::*;
use std::collections::HashSet;

pub fn get_active_network_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();
    unsafe {
        // 1. IPv4 TCP connections
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            if GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ) == 0 {
                let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                let num_entries = (*table).dwNumEntries;
                let rows = std::slice::from_raw_parts((*table).table.as_ptr(), num_entries as usize);
                for row in rows {
                    if row.dwOwningPid > 4 {
                        pids.insert(row.dwOwningPid);
                    }
                }
            }
        }

        // 2. IPv6 TCP connections
        let mut size6 = 0u32;
        let _ = GetExtendedTcpTable(
            null_mut(),
            &mut size6,
            0,
            AF_INET6 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size6 > 0 {
            let mut buf = vec![0u8; size6 as usize];
            if GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size6,
                0,
                AF_INET6 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            ) == 0 {
                let table = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
                let num_entries = (*table).dwNumEntries;
                let rows = std::slice::from_raw_parts((*table).table.as_ptr(), num_entries as usize);
                for row in rows {
                    if row.dwOwningPid > 4 {
                        pids.insert(row.dwOwningPid);
                    }
                }
            }
        }

        // 3. IPv4 UDP endpoints
        let mut udp_size = 0u32;
        let _ = GetExtendedUdpTable(
            null_mut(),
            &mut udp_size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if udp_size > 0 {
            let mut buf = vec![0u8; udp_size as usize];
            if GetExtendedUdpTable(
                buf.as_mut_ptr() as *mut _,
                &mut udp_size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            ) == 0 {
                let table = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
                let num_entries = (*table).dwNumEntries;
                let rows = std::slice::from_raw_parts((*table).table.as_ptr(), num_entries as usize);
                for row in rows {
                    if row.dwOwningPid > 4 {
                        pids.insert(row.dwOwningPid);
                    }
                }
            }
        }

        // 4. IPv6 UDP endpoints
        let mut udp_size6 = 0u32;
        let _ = GetExtendedUdpTable(
            null_mut(),
            &mut udp_size6,
            0,
            AF_INET6 as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if udp_size6 > 0 {
            let mut buf = vec![0u8; udp_size6 as usize];
            if GetExtendedUdpTable(
                buf.as_mut_ptr() as *mut _,
                &mut udp_size6,
                0,
                AF_INET6 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            ) == 0 {
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
    }
    pids
}

pub fn terminate_tcp_connections_for_pids(target_pids: &HashSet<u32>) {
    if target_pids.is_empty() {
        return;
    }
    unsafe {
        let mut size = 0u32;
        let _ = GetExtendedTcpTable(
            null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if size > 0 {
            let mut buf = vec![0u8; size as usize];
            let ret = GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if ret == 0 {
                let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                let num_entries = (*table).dwNumEntries;
                let rows = std::slice::from_raw_parts((*table).table.as_ptr(), num_entries as usize);
                for row in rows {
                    if target_pids.contains(&row.dwOwningPid) {
                        let mut tcp_row: MIB_TCPROW_LH = std::mem::zeroed();
                        tcp_row.Anonymous.dwState = 12; // MIB_TCP_STATE_DELETE_TCB
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

    if ret == 111 { // ERROR_BUFFER_OVERFLOW
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
        return Err(format!("GetAdaptersAddresses failed with error code {}", ret));
    }

    let mut out = Vec::new();
    let mut curr = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

    while !curr.is_null() {
        let adapter = unsafe { &*curr };

        // Friendly name
        let name = if !adapter.FriendlyName.is_null() {
            let mut len = 0;
            while unsafe { *adapter.FriendlyName.add(len) } != 0 { len += 1; }
            let slice = unsafe { std::slice::from_raw_parts(adapter.FriendlyName, len) };
            String::from_utf16_lossy(slice)
        } else {
            "Unknown Adapter".into()
        };

        // Description
        let description = if !adapter.Description.is_null() {
            let mut len = 0;
            while unsafe { *adapter.Description.add(len) } != 0 { len += 1; }
            let slice = unsafe { std::slice::from_raw_parts(adapter.Description, len) };
            String::from_utf16_lossy(slice)
        } else {
            String::new()
        };

        let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        let is_up = adapter.OperStatus == 1; // IfOperStatusUp
        let status = if is_up { "Up" } else { "Down" }.to_string();

        // Extract IPv4 address
        let mut ipv4: Option<String> = None;
        let mut unicast = adapter.FirstUnicastAddress;
        while !unicast.is_null() {
            let u = unsafe { &*unicast };
            let sa = u.Address.lpSockaddr;
            if !sa.is_null() && unsafe { (*sa).sa_family } == AF_INET {
                let sin = unsafe { &*(sa as *const SOCKADDR_IN) };
                let bytes = unsafe { sin.sin_addr.S_un.S_un_b };
                let ip = Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4);
                if !ip.is_loopback() {
                    ipv4 = Some(ip.to_string());
                    break;
                }
            }
            unicast = u.Next;
        }

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
                status,
                description,
                ipv4,
                gateway,
                virtual_adapter,
            });
        }

        curr = adapter.Next;
    }

    out.sort_by(|a, b| a.index.cmp(&b.index));
    Ok(out)
}

pub fn is_likely_vpn(i: &InterfaceInfo) -> bool {
    let s = format!("{} {}", i.name, i.description).to_ascii_lowercase();
    let keywords = [
        "wireguard", "wintun", "openvpn", "tap", "tun", "tailscale",
        "warp", "vpn", "fortinet", "cisco", "hamachi", "zerotier",
        "v2ray", "xray", "sing-box", "nekoray", "clash", "hiddify"
    ];
    keywords.iter().any(|k| s.contains(k)) || i.virtual_adapter
}
