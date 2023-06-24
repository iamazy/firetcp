use nix::ifaddrs::getifaddrs;

use crate::{error::FireResult, ethernet::EthernetAddress, FireError};

pub struct NetworkInterface {
    pub mac_addr: EthernetAddress,
    pub ip_addr: u32,
    // interface index
    pub iface_index: usize,
}

pub fn get_local_ip_addr(name: Option<&str>) -> FireResult<NetworkInterface> {
    let ifiter = getifaddrs()?;
    let mut ip_addr = None;
    let mut mac_addr = None;
    let mut iface_index = None;
    for interface in ifiter {
        if let Some(name) = name {
            if interface.interface_name == name {
                if let Some(storage) = interface.address {
                    if let Some(link_addr) = storage.as_link_addr() {
                        iface_index = Some(link_addr.ifindex());
                        if let Some(bytes) = link_addr.addr() {
                            mac_addr = Some(bytes);
                        }
                    }
                    if let Some(socket_addr) = storage.as_sockaddr_in() {
                        ip_addr = Some(socket_addr.ip());
                    }
                }
            }
        }
    }
    match (mac_addr, ip_addr, iface_index) {
        (Some(mac_addr), Some(ip_addr), Some(iface_index)) => Ok(NetworkInterface {
            mac_addr: EthernetAddress::from_bytes(&mac_addr),
            ip_addr,
            iface_index,
        }),
        _ => Err(FireError::NoDeviceFound),
    }
}
