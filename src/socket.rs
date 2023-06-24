use std::{os::fd::RawFd, sync::Arc};

use nix::{
    libc::{sa_family_t, sockaddr, sockaddr_ll, AF_PACKET, ETH_P_IP},
    sys::socket::{
        bind, recvfrom, sendto, socket, AddressFamily, LinkAddr, MsgFlags, SockFlag, SockProtocol,
        SockType, SockaddrLike, SockaddrStorage,
    },
    unistd::close,
};

use crate::{ethernet::EthernetAddress, FireResult};

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

pub fn channel(ifindex: usize, mac_addr: EthernetAddress) -> FireResult<(Sender, Receiver)> {
    let socket = socket(
        AddressFamily::Packet,
        SockType::Raw,
        SockFlag::empty(),
        SockProtocol::EthAll,
    )?;

    let mut sockaddr = sockaddr_ll {
        sll_family: AF_PACKET as sa_family_t,
        sll_protocol: (ETH_P_IP as u16).to_be(),
        sll_ifindex: ifindex as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 6,
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
