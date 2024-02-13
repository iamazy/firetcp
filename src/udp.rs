use std::ops::Range;

use bytes::{Buf, BufMut, BytesMut};

use crate::{
    checksum, error::FireResult, ethernet::EthernetFrame, ipv4::Address, socket::channel,
    EtherType, FireError, IpProtocol, Ipv4Packet,
};

/// **User Datagram Protocol** (**UDP**) is one of the core communication protocols of the Internet
/// protocol suite used to send messages (transported as datagrams in packets) to other hosts on an
/// Internet Protocol (IP) network. Within an IP network, UDP does not require prior communication
/// to set up communication channels or data paths.
///
/// UDP uses a simple connectionless communication model with a minimum of protocol mechanisms.
/// UDP provides checksums for data integrity, and port numbers for addressing different functions
/// at the source and destination of the datagram. It has no handshaking dialogues and thus exposes
/// the user's program to any unreliability of the underlying network; there is no guarantee of
/// delivery, ordering, or duplicate protection. If error-correction facilities are needed at the
/// network interface level, an application may instead use Transmission Control Protocol (TCP) or
/// Stream Control Transmission Protocol (SCTP) which are designed for this purpose.
///
/// UDP is suitable for purposes where error checking and correction are either not necessary or are
/// performed in the application; UDP avoids the overhead of such processing in the protocol stack.
/// Time-sensitive applications often use UDP because dropping packets is preferable to waiting for
/// packets delayed due to retransmission, which may not be an option in a real-time system.
///
/// See also [UDP Datagram Header](https://en.wikipedia.org/wiki/User_Datagram_Protocol#UDP_datagram_structure)
#[derive(Debug)]
pub struct UdpPacket {
    buffer: BytesMut,
}

impl UdpPacket {
    // Source port
    const SRC_PORT: Range<usize> = 0..2;
    // Target port
    const DST_PORT: Range<usize> = 2..4;
    const PKT_LEN: Range<usize> = 4..6;
    const CHECKSUM: Range<usize> = 6..8;
    const HEADER_LEN: usize = Self::CHECKSUM.end;

    pub fn new(
        source_ip_addr: Address,
        source_port: u16,
        target_ip_addr: Address,
        target_port: u16,
        payload: &[u8],
    ) -> Self {
        let mut buffer = BytesMut::with_capacity(8);
        buffer.put_u16(source_port);
        buffer.put_u16(target_port);
        // packet length
        buffer.put_u16(0);
        // checksum
        buffer.put_u16(0);

        let mut udp = Self { buffer };
        udp.set_payload(payload);
        udp.fill_checksum(&source_ip_addr, &target_ip_addr);
        udp
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
    /// Returns `Err(BufferTooShort)` if the length field has a value smaller
    /// than the header length.
    pub fn check_len(&self) -> FireResult<()> {
        let buffer_len = self.buffer.as_ref().len();
        if buffer_len < Self::HEADER_LEN {
            Err(FireError::BufferTooShort)
        } else {
            let field_len = self.len();
            if buffer_len < field_len || field_len < Self::HEADER_LEN {
                Err(FireError::BufferTooShort)
            } else {
                Ok(())
            }
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Identify the sender's port, when used, and should be assumed to be the port
    /// to reply to if needed. If not used, it should be zero.
    /// If the source host is the client, the port number is likely to be an ephemeral port.
    /// If the source host is the server, the port number is likely to be a well-known port number
    /// from 0 to 1023.
    pub fn source_port(&self) -> u16 {
        (&self.buffer[Self::SRC_PORT]).get_u16()
    }

    pub fn set_source_port(&mut self, port: u16) {
        let data = self.buffer.as_mut();
        data[Self::SRC_PORT].copy_from_slice(&port.to_be_bytes());
    }

    /// Identify the receiver's port and is required. Similar to source port number,
    /// if the client is the destination host then the port number will likely be an ephemeral port
    /// number and if the destination host is the server then the port number will likely be a
    /// well-known port number.
    pub fn target_port(&self) -> u16 {
        (&self.buffer[Self::DST_PORT]).get_u16()
    }

    pub fn set_target_port(&mut self, port: u16) {
        let data = self.buffer.as_mut();
        data[Self::DST_PORT].copy_from_slice(&port.to_be_bytes());
    }

    /// Specify the length in bytes of the UDP header and UDP data. The minimum length is 8 bytes,
    /// the length of the header. The field size sets a theoretical limit of 65,535 bytes
    /// (8-byte header + 65,527 bytes of data) for a UDP datagram. However, the actual limit
    /// for the data length, which is imposed by the underlying IPv4 protocol, is 65,507 bytes
    /// (65,535 bytes − 8-byte UDP header − 20-byte IP header). Using IPv6 jumbograms
    /// it is possible to have UDP datagrams of size greater than 65,535 bytes. RFC 2675 specifies
    /// that the length field is set to zero if the length of the UDP header plus UDP data is
    /// greater than 65,535.
    pub fn packet_len(&self) -> u16 {
        (&self.buffer[Self::PKT_LEN]).get_u16()
    }

    fn set_packet_len(&mut self, len: u16) {
        let data = self.buffer.as_mut();
        data[Self::PKT_LEN].copy_from_slice(&len.to_be_bytes());
    }

    pub fn payload(&self, len: usize) -> &[u8] {
        &self.buffer[Self::CHECKSUM.end..len]
    }

    pub fn set_payload(&mut self, payload: &[u8]) {
        let len = payload.len();
        let total_len = Self::CHECKSUM.end + len;
        if self.len() < total_len {
            self.buffer.resize(total_len, 0x00);
        }
        (&mut self.buffer[Self::CHECKSUM.end..total_len]).put_slice(payload);
        self.set_packet_len(total_len as u16)
    }

    /// The checksum field may be used for error-checking of the header and data. This field is
    /// optional in IPv4, and mandatory in most cases in IPv6. The field carries all-zeros if
    /// unused.
    pub fn checksum(&self) -> u16 {
        (&self.buffer[Self::CHECKSUM]).get_u16()
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        let data = self.buffer.as_mut();
        data[Self::CHECKSUM].copy_from_slice(&checksum.to_be_bytes());
    }

    /// Compute and fill in the header checksum.
    ///
    /// # Panics
    /// This function panics unless `src_addr` and `dst_addr` belong to the same family,
    /// and that family is IPv4 or IPv6.
    pub fn fill_checksum(&mut self, src_addr: &Address, dst_addr: &Address) {
        self.set_checksum(0);
        let checksum = {
            let buffer = self.buffer.as_ref();
            let packet_len = self.packet_len() as usize;
            !checksum::combine(&[
                checksum::pseudo_header(src_addr, dst_addr, IpProtocol::Udp, packet_len),
                checksum::data(&buffer[..packet_len]),
            ])
        };
        // UDP checksum value of 0 means no checksum; if the checksum really is zero,
        // use all-ones, which indicates that the remote end must verify the checksum.
        // Arithmetically, RFC 1071 checksums of all-zeroes and all-ones behave identically,
        // so no action is necessary on the remote end.
        self.set_checksum(if checksum == 0 { 0xffff } else { checksum })
    }

    pub fn send(
        &self,
        frame: EthernetFrame,
        ip_packet: Ipv4Packet,
        ifindex: usize,
    ) -> FireResult<()> {
        let (sender, _) = channel(EtherType::Ipv4, ifindex, frame.source_mac_address())?;

        let mut packet = vec![];
        packet.extend_from_slice(frame.as_ref());
        packet.extend_from_slice(ip_packet.as_ref());
        packet.extend_from_slice(self.buffer.as_ref());

        let _ret = sender.sendto(packet)?;
        Ok(())
    }
}

impl AsRef<[u8]> for UdpPacket {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}
