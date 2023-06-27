use std::ops::Range;

use bytes::{Buf, BufMut, BytesMut};
use tracing::debug;

use crate::{
    checksum, ethernet::EthernetFrame, socket::channel, EtherType, FireError, FireResult,
    IpProtocol, Ipv4Packet,
};

/// The Internet Control Message Protocol (ICMP) is a supporting protocol in the Internet protocol
/// suite. It is used by network devices, including routers, to send error messages and operational
/// information indicating success or failure when communicating with another IP address, for
/// example, an error is indicated when a requested service is not available or that a host or
/// router could not be reached. ICMP differs from transport protocols such as TCP and UDP in
/// that it is not typically used to exchange data between systems, nor is it regularly employed by
/// end-user network applications (with the exception of some diagnostic tools like ping and
/// traceroute).
#[derive(Debug)]
pub struct IcmpPacket {
    buffer: BytesMut,
}

impl AsRef<[u8]> for IcmpPacket {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

/// Internet protocol control message type.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessageType {
    /// Echo reply
    EchoReply = 0,
    /// Destination unreachable
    DstUnreachable = 3,
    /// Message redirect
    Redirect = 5,
    /// Echo request
    EchoRequest = 8,
    /// Router advertisement
    RouterAdvert = 9,
    /// Router solicitation
    RouterSolicit = 10,
    /// Time exceeded
    TimeExceeded = 11,
    /// Parameter problem
    ParamProblem = 12,
    /// Timestamp
    Timestamp = 13,
    /// Timestamp reply
    TimestampReply = 14,
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            0 => MessageType::EchoReply,
            3 => MessageType::DstUnreachable,
            5 => MessageType::Redirect,
            8 => MessageType::EchoRequest,
            9 => MessageType::RouterAdvert,
            10 => MessageType::RouterSolicit,
            11 => MessageType::TimeExceeded,
            12 => MessageType::ParamProblem,
            13 => MessageType::Timestamp,
            14 => MessageType::TimestampReply,
            _ => panic!("Invalid icmp message type."),
        }
    }
}

/// A high-level representation of an Internet Control Message Protocol version 4 packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum Message<'a> {
    EchoRequest {
        ident: u16,
        seq_no: u16,
        data: &'a [u8],
    },
    EchoReply {
        ident: u16,
        seq_no: u16,
        data: &'a [u8],
    },
}

impl Message<'_> {
    pub fn r#type(&self) -> MessageType {
        match *self {
            Message::EchoRequest { .. } => MessageType::EchoRequest,
            Message::EchoReply { .. } => MessageType::EchoReply,
        }
    }

    pub fn code(&self) -> u8 {
        match *self {
            Message::EchoRequest { .. } | Message::EchoReply { .. } => 0,
        }
    }
}

impl IcmpPacket {
    const TYPE: usize = 0;
    const CODE: usize = 1;
    const CHECKSUM: Range<usize> = 2..4;
    #[allow(dead_code)]
    const UNUSED: Range<usize> = 4..8;
    const ECHO_IDENT: Range<usize> = 4..6;
    const ECHO_SEQNO: Range<usize> = 6..8;
    const HEADER_END: usize = 8;

    pub fn new(msg: Message) -> FireResult<Self> {
        let mut buffer = BytesMut::with_capacity(10);
        // message type
        buffer.put_u8(msg.r#type() as u8);
        // message code
        buffer.put_u8(msg.code());
        // checksum
        buffer.put_u16(0);

        match msg {
            Message::EchoRequest {
                ident,
                seq_no,
                data,
            } => {
                buffer.put_u16(ident);
                buffer.put_u16(seq_no);
                buffer.put_slice(data);
            }
            Message::EchoReply {
                ident,
                seq_no,
                data,
            } => {
                buffer.put_u16(ident);
                buffer.put_u16(seq_no);
                buffer.put_slice(data);
            }
        }

        let mut icmp = IcmpPacket::new_checked(&buffer)?;
        icmp.fill_checksum();

        Ok(icmp)
    }

    pub fn new_checked(buffer: &[u8]) -> FireResult<Self> {
        let buffer = BytesMut::from(buffer);
        let icmp = IcmpPacket { buffer };
        icmp.check_len()?;
        Ok(icmp)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(BufferTooShort)` if the buffer is too short.
    pub fn check_len(&self) -> FireResult<()> {
        let len = self.buffer.as_ref().len();
        if len < Self::HEADER_END {
            Err(FireError::BufferTooShort)
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

    /// Return the header length.
    /// The result depends on the value of the message type field.
    pub fn header_len(&self) -> usize {
        match self.message_type() {
            MessageType::EchoRequest => Self::ECHO_SEQNO.end,
            MessageType::EchoReply => Self::ECHO_SEQNO.end,
            _ => Self::UNUSED.end,
        }
    }

    /// Return the message type field.
    ///
    /// See also [Control messages](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)
    #[inline]
    pub fn message_type(&self) -> MessageType {
        let data = self.buffer.as_ref();
        data[Self::TYPE].into()
    }

    /// Set the message type field.
    #[inline]
    pub fn set_message_type(&mut self, value: MessageType) {
        let data = self.buffer.as_mut();
        data[Self::TYPE] = value as u8
    }

    /// Return the message code field.
    ///
    /// See also [Control messages](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)
    #[inline]
    pub fn message_code(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[Self::CODE]
    }

    /// Set the message code field.
    #[inline]
    pub fn set_message_code(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[Self::CODE] = value
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        (&data[Self::CHECKSUM]).get_u16()
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        (&mut data[Self::CHECKSUM]).put_u16(value)
    }

    /// Return the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn echo_ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        (&data[Self::ECHO_IDENT]).get_u16()
    }

    /// Set the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn set_echo_ident(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        (&mut data[Self::ECHO_IDENT]).put_u16(value)
    }

    /// Return the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn echo_seq_no(&self) -> u16 {
        let data = self.buffer.as_ref();
        (&data[Self::ECHO_SEQNO]).get_u16()
    }

    /// Set the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn set_echo_seq_no(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        (&mut data[Self::ECHO_SEQNO]).put_u16(value)
    }

    #[inline]
    pub fn echo_data(&self) -> &[u8] {
        let data = self.buffer.as_ref();
        &data[self.header_len()..]
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        let data = self.buffer.as_ref();
        checksum::data(data) == !0
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(data)
        };
        self.set_checksum(checksum)
    }

    pub fn send(
        &self,
        frame: EthernetFrame,
        ip_packet: Ipv4Packet,
        ifindex: usize,
    ) -> FireResult<Self> {
        let (sender, mut receiver) = channel(EtherType::Ipv4, ifindex, frame.source_mac_address())?;

        let mut packet = vec![];
        packet.extend_from_slice(frame.as_ref());
        packet.extend_from_slice(ip_packet.as_ref());
        packet.extend_from_slice(self.buffer.as_ref());

        let ret = sender.sendto(packet)?;
        debug!("send icmp request: {}, bufsize: {}", self, ret);

        loop {
            let (ret, _addr) = receiver.recvfrom()?;
            if ret > 0 {
                assert!(ret >= 34, "Invalid ethernet packet");
                let frame = EthernetFrame::new_checked(&receiver.buf)?;
                if !matches!(frame.ether_type(), EtherType::Ipv4) {
                    continue;
                }

                let ipv4 = Ipv4Packet::new_checked(frame.payload())?;
                if !matches!(ipv4.protocol(), IpProtocol::Icmp) {
                    continue;
                }

                let icmp_reply = IcmpPacket::new_checked(ipv4.payload())?;
                debug!("received icmp reply: {icmp_reply}, bufsize: {ret}",);
                return Ok(icmp_reply);
            }
        }
    }
}

impl std::fmt::Display for IcmpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg_type = self.message_type();
        write!(
            f,
            "message type: {:?}, message code: {}",
            msg_type,
            self.message_code()
        )?;
        match msg_type {
            MessageType::EchoRequest | MessageType::EchoReply => {
                write!(
                    f,
                    ", ident: {}, sequence number: {}, data len: {}",
                    self.echo_ident(),
                    self.echo_seq_no(),
                    self.echo_data().len()
                )?;
            }
            _ => {}
        }
        Ok(())
    }
}
