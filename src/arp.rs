use std::ops::Range;

use bytes::{BufMut, BytesMut};
use tracing::debug;

use crate::{
    error::FireResult,
    ethernet::{EtherType, EthernetAddress, EthernetFrame},
    ipv4::Address,
    socket::channel,
    FireError, NetworkInterface,
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
        source_mac_addr: EthernetAddress,
        source_ip_addr: Address,
        target_mac_addr: EthernetAddress,
        target_ip_addr: Address,
        op: OpCode,
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
        buffer.put_slice(&op.to_bytes());
        // source hardware addr
        buffer.put_slice(source_mac_addr.as_bytes());
        // source protocol addr
        buffer.put_slice(source_ip_addr.as_bytes());
        // target hardware addr
        buffer.put_slice(target_mac_addr.as_bytes());
        // target protocol addr
        buffer.put_slice(target_ip_addr.as_bytes());

        let arp = Self { buffer };
        arp.check_len()?;
        Ok(arp)
    }

    pub fn new_gratuitous(
        source_mac_addr: EthernetAddress,
        source_ip_addr: Address,
    ) -> FireResult<Self> {
        Self::new(
            source_mac_addr,
            source_ip_addr,
            EthernetAddress::BROADCAST,
            source_ip_addr,
            OpCode::Reply,
        )
    }

    pub fn new_announcement(
        source_mac_addr: EthernetAddress,
        source_ip_addr: Address,
    ) -> FireResult<Self> {
        Self::new(
            source_mac_addr,
            source_ip_addr,
            EthernetAddress::BROADCAST,
            source_ip_addr,
            OpCode::Request,
        )
    }

    pub fn new_checked(packet: &[u8]) -> FireResult<Self> {
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

    pub fn set_source_hardware_address(&mut self, addr: EthernetAddress) {
        let sha = Self::SHA(self.hardware_len(), self.protocol_len());
        let data = self.buffer.as_mut();
        (&mut data[sha]).put_slice(addr.as_bytes());
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

    pub fn set_target_hardware_address(&mut self, addr: EthernetAddress) {
        let tha = Self::THA(self.hardware_len(), self.protocol_len());
        let data = self.buffer.as_mut();
        (&mut data[tha]).put_slice(addr.as_bytes());
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

    pub fn send(&mut self, iface: NetworkInterface) -> FireResult<Option<Self>> {
        let frame = EthernetFrame::new(EthernetAddress::BROADCAST, iface.mac_addr, EtherType::Arp);

        let (sender, mut receiver) = channel(
            EtherType::Arp,
            iface.iface_index,
            frame.source_mac_address(),
        )?;

        let mut packet = vec![];
        packet.extend_from_slice(frame.as_ref());
        packet.extend_from_slice(self.buffer.as_ref());

        let ret = sender.sendto(packet)?;
        match self.operation() {
            OpCode::Request => {
                debug!("send arp request: {}, bufsize: {}", self, ret);
                loop {
                    let (ret, _addr) = receiver.recvfrom()?;
                    if ret > 0 {
                        let frame = EthernetFrame::new_checked(&receiver.buf)?;
                        if !matches!(frame.ether_type(), EtherType::Arp) {
                            continue;
                        }
                        let arp = Arp::new_checked(frame.payload())?;
                        if let OpCode::Reply = arp.operation() {
                            debug!("received arp reply: {}, bufsize: {}", arp, ret);
                            return Ok(Some(arp));
                        }
                    }
                }
            }
            OpCode::Reply => {
                debug!("send arp reply: {}, bufsize: {}", self, ret);
                Ok(None)
            }
        }
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
