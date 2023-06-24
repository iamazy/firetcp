use bytes::{Bytes, BytesMut};

/// A six-octet Ethernet II address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct EthernetAddress([u8; 6]);

impl EthernetAddress {
    /// The broadcast address.
    pub const BROADCAST: EthernetAddress = EthernetAddress([0xff; 6]);

    pub const fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Construct an Ethernet address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not six octets long.
    pub fn from_bytes(data: &[u8]) -> EthernetAddress {
        let mut bytes = [0; 6];
        bytes.copy_from_slice(data);
        EthernetAddress(bytes)
    }

    /// Return an Ethernet address as a sequence of octets, in big-endian.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast())
    }

    /// Query whether this address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Query whether the "multicast" bit in the OUI is set.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Query whether the "locally administered" bit in the OUI is set.
    pub const fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl std::fmt::Display for EthernetAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let bytes = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

/// EtherType is a two-octet field in an Ethernet frame. It is used to indicate which protocol is
/// encapsulated in the payload of the frame and is used at the receiving end by the data link layer
/// to determine how the payload is processed. The same field is also used to indicate the size of
/// some Ethernet frames.
///
/// EtherType is also used as the basis of 802.1Q VLAN tagging, encapsulating packets from VLANs for
/// transmission multiplexed with other VLAN traffic over an Ethernet trunk.
///
/// EtherType was first defined by the Ethernet II framing standard and later adapted for the IEEE
/// 802.3 standard. EtherType values are assigned by the IEEE Registration Authority.
///
/// See also [EtherType](https://en.wikipedia.org/wiki/EtherType)
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum EtherType {
    Ipv4 = 0x0800,
    Arp = 0x0806,
}

impl EtherType {
    pub fn to_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

impl<'a> From<&'a [u8]> for EtherType {
    fn from(value: &'a [u8]) -> Self {
        match *value {
            [0x08, 0x00] => EtherType::Ipv4,
            [0x08, 0x06] => EtherType::Arp,
            _ => unimplemented!("Invalid EtherType"),
        }
    }
}

/// In computer networking, an Ethernet frame is a data link layer protocol data unit and uses the
/// underlying Ethernet physical layer transport mechanisms. In other words, a data unit on an
/// Ethernet link transports an Ethernet frame as its payload.
///
/// An Ethernet frame is preceded by a preamble and start frame delimiter (SFD), which are both part
/// of the Ethernet packet at the physical layer. Each Ethernet frame starts with an Ethernet
/// header, which contains destination and source MAC addresses as its first two fields. The middle
/// section of the frame is payload data including any headers for other protocols (for example,
/// Internet Protocol) carried in the frame. The frame ends with a frame check sequence (FCS), which
/// is a 32-bit cyclic redundancy check used to detect any in-transit corruption of data.
///
/// See also [EthernetFrame](https://en.wikipedia.org/wiki/Ethernet_frame)
pub struct EthernetFrame {
    buffer: Bytes,
}

impl EthernetFrame {
    pub fn new(
        dst_mac_addr: EthernetAddress,
        src_mac_addr: EthernetAddress,
        ether_type: EtherType,
    ) -> Self {
        let mut buffer = BytesMut::with_capacity(14);
        buffer.extend_from_slice(dst_mac_addr.as_bytes());
        buffer.extend_from_slice(src_mac_addr.as_bytes());
        buffer.extend_from_slice(&ether_type.to_bytes());
        Self {
            buffer: buffer.freeze(),
        }
    }

    /// Destination MAC address
    pub fn target_mac_address(&self) -> EthernetAddress {
        EthernetAddress::from_bytes(&self.buffer[0..6])
    }

    /// Source MAC address
    pub fn source_mac_address(&self) -> EthernetAddress {
        EthernetAddress::from_bytes(&self.buffer[6..12])
    }

    pub fn ether_type(&self) -> EtherType {
        self.buffer[12..].into()
    }
}

impl AsRef<[u8]> for EthernetFrame {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::{EtherType, EthernetFrame};
    use crate::ethernet::EthernetAddress;

    #[test]
    fn ethernet_frame() {
        let src_mac_addr = [0xffu8; 6];
        let dst_mac_addr = [0x00u8; 6];

        let frame = EthernetFrame::new(
            EthernetAddress(dst_mac_addr),
            EthernetAddress(src_mac_addr),
            EtherType::Arp,
        );
        assert_eq!(frame.as_ref().len(), 14);
        assert_eq!(
            frame.as_ref(),
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x08, 0x06]
        );
        assert_eq!(
            frame.source_mac_address().as_bytes(),
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            frame.target_mac_address().as_bytes(),
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(frame.ether_type(), EtherType::Arp);
    }
}
