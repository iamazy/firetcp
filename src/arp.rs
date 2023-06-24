use std::ops::Range;

use bytes::{BufMut, BytesMut};
use nix::{
    sys::socket::{
        bind, recvfrom, sendto, socket, AddressFamily, LinkAddr, MsgFlags, SockFlag, SockProtocol,
        SockType, SockaddrLike, SockaddrStorage,
    },
    unistd::close,
};
use tracing::debug;

use crate::{
    error::FireResult,
    ethernet::{EtherType, EthernetAddress, EthernetFrame},
    ipv4::Address,
    FireError,
};

/// The Address Resolution Protocol (ARP) is a communication protocol used for discovering the link
/// layer address, such as a MAC address, associated with a given internet layer address, typically
/// an IPv4 address. This mapping is a critical function in the Internet protocol suite. ARP was
/// defined in 1982 by RFC 826,[1] which is Internet Standard STD 37. ARP has been implemented with
/// many combinations of network and data link layer technologies, such as IPv4, Chaosnet,
/// DECnet and Xerox PARC Universal Packet (PUP) using IEEE 802 standards, FDDI, X.25, Frame Relay
/// and Asynchronous Transfer Mode (ATM).
///
/// In Internet Protocol Version 6 (IPv6) networks, the functionality of ARP is provided by the
/// Neighbor Discovery Protocol (NDP).
///
/// See also [Address Resolution Protocol](https://en.wikipedia.org/wiki/Address_Resolution_Protocol)
#[derive(Debug)]
pub struct Arp {
    buffer: BytesMut,
}

impl Arp {
    const HTYPE: Range<usize> = 0..2;
    const PTYPE: Range<usize> = 2..4;
    const HLEN: usize = 4;
    const PLEN: usize = 5;
    const OPER: Range<usize> = 6..8;

    #[inline]
    const fn SHA(hardware_len: u8, _protocol_len: u8) -> Range<usize> {
        let start = Self::OPER.end;
        start..(start + hardware_len as usize)
    }

    #[inline]
    const fn SPA(hardware_len: u8, protocol_len: u8) -> Range<usize> {
        let start = Self::SHA(hardware_len, protocol_len).end;
        start..(start + protocol_len as usize)
    }

    #[inline]
    const fn THA(hardware_len: u8, protocol_len: u8) -> Range<usize> {
        let start = Self::SPA(hardware_len, protocol_len).end;
        start..(start + hardware_len as usize)
    }

    #[inline]
    const fn TPA(hardware_len: u8, protocol_len: u8) -> Range<usize> {
        let start = Self::THA(hardware_len, protocol_len).end;
        start..(start + protocol_len as usize)
    }

    pub fn new(
        mac_addr: EthernetAddress,
        source_ip_addr: Address,
        target_ip_addr: Address,
    ) -> FireResult<Self> {
        let mut buffer = BytesMut::with_capacity(28);
        // hardware type
        buffer.put_slice(&HardwareType::Ethernet.to_bytes());
        // protocol type
        buffer.put_slice(&EtherType::Ipv4.to_bytes());
        // hardware len
        buffer.put_u8(6);
        // protocol len
        buffer.put_u8(4);
        // operation
        buffer.put_slice(&OpCode::Request.to_bytes());
        // source hardware addr
        buffer.put_slice(mac_addr.as_bytes());
        // source protocol addr
        buffer.put_slice(source_ip_addr.as_bytes());
        // target hardware addr
        buffer.put_slice(&[0x00; 6]);
        // target protocol addr
        buffer.put_slice(target_ip_addr.as_bytes());

        let arp = Self { buffer };
        arp.check_len()?;
        Ok(arp)
    }

    fn new_checked(packet: &[u8]) -> FireResult<Self> {
        let buffer = BytesMut::from(packet);
        let arp = Arp { buffer };
        arp.check_len()?;
        Ok(arp)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(BufferTooShort)` if the buffer is too short.
    #[allow(clippy::if_same_then_else)]
    pub fn check_len(&self) -> FireResult<()> {
        let len = self.len();
        if len < Self::OPER.end {
            Err(FireError::BufferTooShort)
        } else if len < Self::TPA(self.hardware_len(), self.protocol_len()).end {
            Err(FireError::BufferTooShort)
        } else {
            Ok(())
        }
    }

    /// Return the length of arp packet
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Specify the network link protocol type (HTYPE, 2 bytes).
    ///
    /// e.g. Ethernet is 1.
    ///
    /// See also [Hardware Types](https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2).
    pub fn hardware_type(&self) -> HardwareType {
        self.buffer[Self::HTYPE].into()
    }

    /// Specify the internetwork protocol (PTYPE, 2 bytes) for which the ARP request is intended.
    /// For IPv4, this has the value 0x0800. The permitted PTYPE values share a numbering space
    /// with those for EtherType.
    ///
    /// See also [EtherType](https://en.wikipedia.org/wiki/EtherType#Values).
    pub fn protocol_type(&self) -> EtherType {
        self.buffer[Self::PTYPE].into()
    }

    /// Length (in octets) of a hardware address (HLEN, 1 byte).
    ///
    /// e.g. Ethernet address length is 6.
    pub fn hardware_len(&self) -> u8 {
        self.buffer[Self::HLEN]
    }

    /// Length (in octets) of internetwork addresses (PLEN, 1 byte). The internetwork protocol is
    /// specified in PTYPE.
    ///
    /// e.g. IPv4 address length is 4.
    pub fn protocol_len(&self) -> u8 {
        self.buffer[Self::PLEN]
    }

    /// Specify the operation that the sender is performing (2 bytes).
    ///
    /// e.g. 1 for request, 2 for reply.
    ///
    /// See also [Operation Codes](https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-1).
    pub fn operation(&self) -> OpCode {
        self.buffer[Self::OPER].into()
    }

    /// MAC address of the sender (SHA, 6 bytes). In an ARP request this field is used to indicate
    /// the address of the host sending the request. In an ARP reply this field is used to
    /// indicate the address of the host that the request was looking for.
    pub fn source_hardware_address(&self) -> EthernetAddress {
        let addr = &self.buffer[Self::SHA(self.hardware_len(), self.protocol_len())];
        EthernetAddress::from_bytes(addr)
    }

    /// Internetwork address of the sender (SPA).
    pub fn source_protocol_address(&self) -> Address {
        let addr = &self.buffer[Self::SPA(self.hardware_len(), self.protocol_len())];
        Address::from_bytes(addr)
    }

    /// MAC address of the intended receiver (THA, 6 bytes). In an ARP request this field is
    /// ignored. In an ARP reply this field is used to indicate the address of the host that
    /// originated the ARP request.
    pub fn target_hardware_address(&self) -> EthernetAddress {
        let addr = &self.buffer[Self::THA(self.hardware_len(), self.protocol_len())];
        EthernetAddress::from_bytes(addr)
    }

    /// Internetwork address of the intended receiver (TPA, 4 bytes).
    pub fn target_protocol_address(&self) -> Address {
        let addr = &self.buffer[Self::TPA(self.hardware_len(), self.protocol_len())];
        Address::from_bytes(addr)
    }

    pub fn check_reply(&self, reply: &Arp) -> bool {
        self.source_hardware_address() == reply.target_hardware_address()
            && self.source_protocol_address() == reply.target_protocol_address()
            && self.target_protocol_address() == reply.source_protocol_address()
    }

    pub fn send(&self, ethernet: EthernetFrame, iface_index: usize) -> FireResult<Option<Self>> {
        let send_fd = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::empty(),
            SockProtocol::EthAll,
        )?;
        // sockaddr_ll is a device-independent physical-layer (data link layer) address.
        //
        // [Further reading](https://man7.org/linux/man-pages/man7/packet.7.html)
        let mut sockaddr = nix::libc::sockaddr_ll {
            // Always AF_PACKET
            sll_family: nix::libc::AF_PACKET as nix::libc::sa_family_t,
            // Physical-layer protocol
            sll_protocol: (nix::libc::ETH_P_ALL as u16).to_be(),
            // interface number
            sll_ifindex: iface_index as i32,
            // ARP hardware type
            sll_hatype: 0,
            // Packet type
            sll_pkttype: 0,
            // Length of MAC address
            sll_halen: 6,
            // Physical-layer address [MAC]
            sll_addr: [0; 8],
        };
        sockaddr.sll_addr[..6].copy_from_slice(ethernet.source_mac_address().as_bytes());
        let addr = unsafe {
            LinkAddr::from_raw(
                &sockaddr as *const nix::libc::sockaddr_ll as *const nix::libc::sockaddr,
                None,
            )
            .unwrap()
        };

        bind(send_fd, &addr)?;

        let mut packet = vec![];
        packet.extend_from_slice(ethernet.as_ref());
        packet.extend_from_slice(self.buffer.as_ref());

        let ret = sendto(send_fd, &packet, &addr, MsgFlags::empty())?;
        debug!("send arp request: {}, bufsize: {}", self, ret);

        let mut recv_buf = vec![0; 4096];
        while let Ok((ret, _addr)) = recvfrom::<SockaddrStorage>(send_fd, &mut recv_buf) {
            if !recv_buf.is_empty() {
                // # Received buffer Example
                //
                // ```ignore
                // 0xffff 0xffff 0xffff        6 bytes, destination mac address
                // 0x0000 0x0012 0x3010        6 bytes, source mac address
                // 0x0806                      2 bytes, ether type, 0x0806 for arp
                // 0x0001                      2 bytes, hardware type, 0x0001 for ethernet
                // |--------------------------- 16 bytes ----------------------------|
                // 0x0800                      2 bytes, protocol type
                // 0x06                        1 byte, length of hardware address
                // 0x04                        1 byte, length of protocol address
                // 0x0001                      2 bytes, operation code, 0x0001 for request, 0x0002 for reply
                // 0x0000 0x0012 0x3010        6 bytes, source hardware address
                // 0x0202 0x0202               4 bytes, source protocol address
                // |--------------------------- 16 bytes ----------------------------|
                // 0x0000 0x0000 0x0000        6 bytes, target hardware address
                // 0x0202 0x0201               4 bytes, target protocol address
                // ```
                if recv_buf[12..14] == [0x08, 0x06] && recv_buf[20..22] == [0x00, 0x02] {
                    let arp_reply = Self::new_checked(&recv_buf[14..])?;
                    if self.check_reply(&arp_reply) {
                        debug!("received arp reply: {}, bufsize: {}", arp_reply, ret);
                        close(send_fd)?;
                        return Ok(Some(arp_reply));
                    }
                }
            }
        }

        Ok(None)
    }
}

impl AsRef<[u8]> for Arp {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl std::fmt::Display for Arp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "hardware type: {:?}, protocol type: {:?}, operation: {:?}, source hardware addr: {}, \
             source ip addr: {}, target hardware addr: {}, target ip addr: {}",
            self.hardware_type(),
            self.protocol_type(),
            self.operation(),
            self.source_hardware_address(),
            self.source_protocol_address(),
            self.target_hardware_address(),
            self.target_protocol_address(),
        )
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum HardwareType {
    Ethernet = 1,
}

impl HardwareType {
    pub fn to_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

impl<'a> From<&'a [u8]> for HardwareType {
    fn from(value: &'a [u8]) -> Self {
        match *value {
            [0x00, 0x01] => HardwareType::Ethernet,
            _ => unimplemented!("Invalid hardware type"),
        }
    }
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum OpCode {
    Request = 1,
    Reply = 2,
}

impl OpCode {
    pub fn to_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

impl<'a> From<&'a [u8]> for OpCode {
    fn from(value: &'a [u8]) -> Self {
        match *value {
            [0x00, 0x01] => OpCode::Request,
            [0x00, 0x02] => OpCode::Reply,
            _ => unimplemented!("Invalid arp operation code"),
        }
    }
}
