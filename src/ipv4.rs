use std::ops::Range;

use bytes::{Buf, BufMut, BytesMut};

use crate::{checksum, FireError, FireResult};

/// Size of IPv4 adderess in octets.
///
/// [RFC 8200 § 2]: https://www.rfc-editor.org/rfc/rfc791#section-3.2
pub const ADDR_SIZE: usize = 4;

/// A four-octet IPv4 address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Address(pub [u8; ADDR_SIZE]);

impl Address {
    /// An unspecified address.
    pub const UNSPECIFIED: Address = Address([0x00; ADDR_SIZE]);

    /// The broadcast address.
    pub const BROADCAST: Address = Address([0xff; ADDR_SIZE]);

    /// All multicast-capable nodes
    pub const MULTICAST_ALL_SYSTEMS: Address = Address([224, 0, 0, 1]);

    /// All multicast-capable routers
    pub const MULTICAST_ALL_ROUTERS: Address = Address([224, 0, 0, 2]);

    /// Construct an IPv4 address from parts.
    pub const fn new(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address([a0, a1, a2, a3])
    }

    /// Construct an IPv4 address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not four octets long.
    pub fn from_bytes(data: &[u8]) -> Address {
        let mut bytes = [0; ADDR_SIZE];
        bytes.copy_from_slice(data);
        Address(bytes)
    }

    /// Return an IPv4 address as a sequence of octets, in big-endian.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast() || self.is_unspecified())
    }

    /// Query whether the address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        self.0[0..4] == [255; ADDR_SIZE]
    }

    /// Query whether the address is a multicast address.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0xf0 == 224
    }

    /// Query whether the address falls into the "unspecified" range.
    pub const fn is_unspecified(&self) -> bool {
        self.0[0] == 0
    }

    /// Query whether the address falls into the "link-local" range.
    pub fn is_link_local(&self) -> bool {
        self.0[0..2] == [169, 254]
    }

    /// Query whether the address falls into the "loopback" range.
    pub const fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }
}

#[cfg(feature = "std")]
impl From<::std::net::Ipv4Addr> for Address {
    fn from(x: ::std::net::Ipv4Addr) -> Address {
        Address(x.octets())
    }
}

#[cfg(feature = "std")]
impl From<Address> for ::std::net::Ipv4Addr {
    fn from(Address(x): Address) -> ::std::net::Ipv4Addr {
        x.into()
    }
}

impl<'a> From<&'a str> for Address {
    fn from(value: &'a str) -> Self {
        let mut addr = Address::UNSPECIFIED;
        for (idx, v) in value.split('.').enumerate() {
            let i = v.parse::<usize>().unwrap();
            addr.0[idx] = i as u8;
        }
        addr
    }
}

impl<'a> From<&'a String> for Address {
    fn from(value: &'a String) -> Self {
        value.as_str().into()
    }
}

impl From<u32> for Address {
    fn from(value: u32) -> Self {
        Self(value.to_be_bytes())
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let bytes = self.0;
        write!(f, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

/// The IPv4 packet header consists of 14 fields, of which 13 are required. The 14th field is
/// optional and aptly named: options. The fields in the header are packed with the most significant
/// byte first (network byte order), and for the diagram and discussion, the most significant bits
/// are considered to come first (MSB 0 bit numbering). The most significant bit is numbered 0, so
/// the version field is actually found in the four most significant bits of the first byte.
///
/// See also [Internet Protocol version 4](https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header)
#[derive(Debug, Clone)]
pub struct Ipv4Packet {
    buffer: BytesMut,
}

/// Ip Protocol
///
/// See also [Ip Protocol Numbers](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpProtocol {
    Icmp = 0x01,
    Tcp = 0x06,
    Udp = 0x11,
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            0x01 => IpProtocol::Icmp,
            0x06 => IpProtocol::Tcp,
            0x11 => IpProtocol::Udp,
            _ => panic!("Invalid Ip protocol"),
        }
    }
}

impl Ipv4Packet {
    const VER_IHL: usize = 0;
    const DSCP_ECN: usize = 1;
    const LENGTH: Range<usize> = 2..4;
    const IDENT: Range<usize> = 4..6;
    const FLG_OFF: Range<usize> = 6..8;
    const TTL: usize = 8;
    const PROTOCOL: usize = 9;
    const CHECKSUM: Range<usize> = 10..12;
    const SRC_ADDR: Range<usize> = 12..16;
    const DST_ADDR: Range<usize> = 16..20;

    pub fn new(
        source_ip: Address,
        target_ip: Address,
        protocol: IpProtocol,
        extra_len: usize,
    ) -> Self {
        let mut buffer = BytesMut::with_capacity(20);
        // version and header length
        buffer.put_u8(0);
        // service_type
        buffer.put_u8(0);
        // total packet length
        buffer.put_u16(0);
        // packet identification
        buffer.put_u16(0);
        // flags and fragment_offset
        buffer.put_slice(&[0x40, 0x00]);
        // ttl
        buffer.put_u8(0x40);
        // protocol
        buffer.put_u8(protocol as u8);
        // checksum
        buffer.put_u16(0);
        buffer.put_slice(source_ip.as_bytes());
        buffer.put_slice(target_ip.as_bytes());

        let mut ip_packet = Self { buffer };
        ip_packet.set_version(4);
        ip_packet.set_header_len(Self::DST_ADDR.end as u8);
        ip_packet.set_total_len((ip_packet.len() + extra_len) as u16);

        ip_packet.fill_checksum();
        ip_packet
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: &[u8]) -> FireResult<Self> {
        let buffer = BytesMut::from(buffer);
        let packet = Self { buffer };
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(BufferTooShort)` if the buffer is too short.
    /// Returns `Err(BufferTooShort)` if the header length is greater
    /// than total length.
    #[allow(clippy::if_same_then_else)]
    pub fn check_len(&self) -> FireResult<()> {
        let len = self.buffer.as_ref().len();
        if len < Self::DST_ADDR.end {
            Err(FireError::BufferTooShort)
        } else if len < self.header_len() as usize {
            Err(FireError::BufferTooShort)
        } else if self.header_len() as u16 > self.total_len() {
            Err(FireError::BufferTooShort)
        } else if len < self.total_len() as usize {
            // Err(FireError::BufferTooShort)
            Ok(())
        } else {
            Ok(())
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Return the version field.
    ///
    /// for IPv4, always equals to 4
    ///
    /// See also [IP version numbers](https://en.wikipedia.org/wiki/List_of_IP_version_numbers)
    #[inline]
    pub fn version(&self) -> u8 {
        self.buffer[Self::VER_IHL] >> 4
    }

    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[Self::VER_IHL] = (data[Self::VER_IHL] & !0xf0) | (value << 4);
    }

    /// Return the header length (IHL), in octets.
    ///
    /// The IPv4 header is variable in size due to the optional 14th field
    /// (options). The IHL field contains the size of the IPv4 header; it has 4 bits that specify
    /// the number of 32-bit words in the header. The minimum value for this field is 5, which
    /// indicates a length of 5 × 32 bits = 160 bits = 20 bytes. As a 4-bit field, the maximum
    /// value is 15; this means that the maximum size of the IPv4 header is 15 × 32 bits = 480 bits
    /// = 60 bytes.
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buffer[Self::VER_IHL] & 0x0f) * 4
    }

    /// Set the header length, in octets.
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[Self::VER_IHL] = (data[Self::VER_IHL] & !0x0f) | ((value / 4) & 0x0f);
    }

    /// Return the Differential Services Code Point field.
    pub fn dscp(&self) -> u8 {
        self.buffer[Self::DSCP_ECN] >> 2
    }

    /// Set the Differential Services Code Point field.
    pub fn set_dscp(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[Self::DSCP_ECN] = (data[Self::DSCP_ECN] & !0xfc) | (value << 2)
    }

    /// Return the Explicit Congestion Notification field.
    pub fn ecn(&self) -> u8 {
        self.buffer[Self::DSCP_ECN] & 0x03
    }

    /// Set the Explicit Congestion Notification field.
    pub fn set_ecn(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[Self::DSCP_ECN] = (data[Self::DSCP_ECN] & !0x03) | (value & 0x03)
    }

    /// Return the total packet length field.
    ///
    /// This 16-bit field defines the entire packet size in bytes, including header and data. The
    /// minimum size is 20 bytes (header without data) and the maximum is 65,535 bytes. All hosts
    /// are required to be able to reassemble datagrams of size up to 576 bytes, but most modern
    /// hosts handle much larger packets. Links may impose further restrictions on the packet size,
    /// in which case datagrams must be fragmented. Fragmentation in IPv4 is performed in either
    /// the sending host or in routers. Reassembly is performed at the receiving host.
    #[inline]
    pub fn total_len(&self) -> u16 {
        let mut len = &self.buffer[Self::LENGTH];
        len.get_u16()
    }

    /// Set the total packet length field.
    #[inline]
    pub fn set_total_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        (&mut data[Self::LENGTH]).put_u16(value)
    }

    /// Return the fragment identification field.
    ///
    /// This field is an identification field and is primarily used for uniquely identifying the
    /// group of fragments of a single IP datagram. Some experimental work has suggested using the
    /// ID field for other purposes, such as for adding packet-tracing information to help trace
    /// datagrams with spoofed source addresses, but RFC 6864 now prohibits any such use.
    #[inline]
    pub fn identification(&self) -> u16 {
        let mut ident = &self.buffer[Self::IDENT];
        ident.get_u16()
    }

    /// Set the fragment identification field.
    #[inline]
    pub fn set_identification(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        (&mut data[Self::IDENT]).put_u16(value)
    }

    /// Return the "don't fragment" (bit 1, DF) flag.
    ///
    /// If the DF flag is set, and fragmentation is required to route the packet, then the packet
    /// is dropped. This can be used when sending packets to a host that does not have resources to
    /// perform reassembly of fragments. It can also be used for path MTU discovery, either
    /// automatically by the host IP software, or manually using diagnostic tools such as ping or
    /// traceroute.
    #[inline]
    pub fn dont_fragment(&self) -> bool {
        let mut data = &self.buffer[Self::FLG_OFF];
        data.get_u16() & 0x4000 != 0
    }

    /// Clear the entire flags field.
    #[inline]
    pub fn clear_flags(&mut self) {
        let mut data = &self.buffer[Self::FLG_OFF];
        let raw = data.get_u16();
        let raw = raw & !0xe000;

        let data = self.buffer.as_mut();
        (&mut data[Self::FLG_OFF]).put_u16(raw)
    }

    /// Return the "more fragments" (bit 2, MF) flag.
    ///
    /// For unfragmented packets, the MF flag is cleared. For fragmented packets,
    /// all fragments except the last have the MF flag set. The last fragment has a non-zero
    /// Fragment Offset field, differentiating it from an unfragmented packet.
    #[inline]
    pub fn more_fragments(&self) -> bool {
        let mut data = &self.buffer[Self::FLG_OFF];
        data.get_u16() & 0x2000 != 0
    }

    /// Set the "more fragments" flag.
    #[inline]
    pub fn set_more_fragments(&mut self, value: bool) {
        let mut data = &self.buffer[Self::FLG_OFF];
        let raw = data.get_u16();
        let raw = if value { raw | 0x2000 } else { raw & !0x2000 };

        let data = self.buffer.as_mut();
        (&mut data[Self::FLG_OFF]).put_u16(raw)
    }

    /// Return the fragment offset, in octets.
    ///
    /// This field specifies the offset of a particular fragment relative to the beginning of the
    /// original unfragmented IP datagram. The fragmentation offset value for the first fragment is
    /// always 0. The field is 13 bits wide, so that the offset can be from 0 to 8191 (from (20
    /// –1) to (213 – 1)). Fragments are specified in units of 8 bytes, which is why fragment
    /// length must be a multiple of 8.[37] Therefore, the 13-bit field allows a maximum offset of
    /// (213 – 1) × 8 = 65,528 bytes, with the header length included (65,528 + 20 = 65,548 bytes),
    /// supporting fragmentation of packets exceeding the maximum IP length of 65,535 bytes.
    #[inline]
    pub fn fragment_offset(&self) -> u16 {
        let mut data = &self.buffer[Self::FLG_OFF];
        data.get_u16() << 3
    }

    /// Set the fragment offset, in octets.
    #[inline]
    pub fn set_fragment_offset(&mut self, value: u16) {
        let mut data = &self.buffer[Self::FLG_OFF];
        let raw = data.get_u16();
        let raw = (raw & 0xe000) | (value >> 3);

        let data = self.buffer.as_mut();
        (&mut data[Self::FLG_OFF]).put_u16(raw)
    }

    /// Return the time to live field.
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.buffer[Self::TTL]
    }

    /// Set the time to live field.
    #[inline]
    pub fn set_ttl(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[Self::TTL] = value
    }

    /// Return the header checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        let mut checksum = &self.buffer[Self::CHECKSUM];
        checksum.get_u16()
    }

    /// Set the header checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        (&mut data[Self::CHECKSUM]).put_u16(value)
    }

    /// Return the next_header (protocol) field.
    #[inline]
    pub fn protocol(&self) -> IpProtocol {
        let data = self.buffer.as_ref();
        let protocol = data[Self::PROTOCOL];
        protocol.into()
    }

    /// Return the source address field.
    #[inline]
    pub fn source_ip_address(&self) -> Address {
        Address::from_bytes(&self.buffer[Self::SRC_ADDR])
    }

    /// Set the source address field.
    #[inline]
    pub fn set_source_ip_address(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[Self::SRC_ADDR].copy_from_slice(value.as_bytes())
    }

    /// Return the destination address field.
    #[inline]
    pub fn target_ip_address(&self) -> Address {
        Address::from_bytes(&self.buffer[Self::DST_ADDR])
    }

    /// Set the destination address field.
    #[inline]
    pub fn set_target_ip_address(&mut self, value: Address) {
        let data = self.buffer.as_mut();
        data[Self::DST_ADDR].copy_from_slice(value.as_bytes())
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(&data[..self.header_len() as usize])
        };
        self.set_checksum(checksum)
    }

    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let range = self.header_len() as usize..self.total_len() as usize;
        let data = self.buffer.as_ref();
        &data[range]
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len() as usize..self.total_len() as usize;
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

impl AsRef<[u8]> for Ipv4Packet {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use crate::ipv4::IpProtocol;

    #[test]
    fn protocol() {
        assert_eq!(IpProtocol::Icmp as u8, 0x01);
        assert_eq!(IpProtocol::Tcp as u8, 0x06);
        assert_eq!(IpProtocol::Udp as u8, 0x11);

        assert_eq!(IpProtocol::Icmp, 0x01.into());
        assert_eq!(IpProtocol::Tcp, 0x06.into());
        assert_eq!(IpProtocol::Udp, 0x11.into());
    }
}
