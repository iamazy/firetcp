use std::{os::fd::RawFd, sync::Arc};

use nix::{
    libc::{sa_family_t, sockaddr, sockaddr_ll, AF_PACKET, ETH_P_ARP, ETH_P_IP},
    sys::socket::{
        bind, recvfrom, sendto, socket, AddressFamily, LinkAddr, MsgFlags, SockFlag, SockProtocol,
        SockType, SockaddrLike, SockaddrStorage,
    },
    unistd::close,
};

use crate::{ethernet::EthernetAddress, EtherType, FireResult, HardwareType};

struct FileDesc {
    fd: RawFd,
}

impl FileDesc {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl Drop for FileDesc {
    fn drop(&mut self) {
        close(self.fd).unwrap();
    }
}

pub struct Sender {
    socket: Arc<FileDesc>,
    addr: LinkAddr,
}

impl Sender {
    pub fn sendto(&self, packet: Vec<u8>) -> FireResult<usize> {
        Ok(sendto(
            self.socket.fd,
            &packet,
            &self.addr,
            MsgFlags::empty(),
        )?)
    }
}

pub struct Receiver {
    socket: Arc<FileDesc>,
    pub buf: Vec<u8>,
}

impl Receiver {
    pub fn recvfrom(&mut self) -> FireResult<(usize, Option<SockaddrStorage>)> {
        Ok(recvfrom::<SockaddrStorage>(self.socket.fd, &mut self.buf)?)
    }
}

pub fn channel(
    ether_type: EtherType,
    ifindex: usize,
    mac_addr: EthernetAddress,
) -> FireResult<(Sender, Receiver)> {
    let socket = socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::empty(),
        SockProtocol::EthAll,
    )?;

    let (protocol, hardware_type) = match ether_type {
        EtherType::Arp => (ETH_P_ARP, HardwareType::Ethernet),
        EtherType::Ipv4 => (ETH_P_IP, HardwareType::Ethernet),
    };

    // sockaddr_ll is a device-independent physical-layer (data link layer) address.
    //
    // [Further reading](https://man7.org/linux/man-pages/man7/packet.7.html)
    let mut sockaddr = sockaddr_ll {
        /// Always AF_PACKET
        sll_family: AF_PACKET as sa_family_t,
        /// Physical-layer protocol
        sll_protocol: (protocol as u16).to_be(),
        /// Interface number
        sll_ifindex: ifindex as libc::c_int,
        /// ARP hardware type
        sll_hatype: hardware_type as libc::c_ushort,
        /// Packet type
        ///
        /// PACKET_HOST: 0
        /// PACKET_BROADCAST: 1
        /// PACKET_MULTICAST: 2
        /// PACKET_OTHERHOST: 3
        /// PACKET_OUTGOING: 4
        sll_pkttype: 0,
        // Length of MAC address
        sll_halen: 6,
        // Physical-layer address [MAC]
        sll_addr: [0; 8],
    };
    sockaddr.sll_addr[..6].copy_from_slice(mac_addr.as_bytes());

    let addr = unsafe {
        LinkAddr::from_raw(&sockaddr as *const sockaddr_ll as *const sockaddr, None).unwrap()
    };

    bind(socket, &addr)?;

    let fd = Arc::new(FileDesc::new(socket));
    let sender = Sender {
        socket: fd.clone(),
        addr,
    };
    let receiver = Receiver {
        socket: fd,
        buf: vec![0; 4096],
    };
    Ok((sender, receiver))
}
