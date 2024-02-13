use firetcp::{
    get_local_ip_addr, Arp, EtherType, EthernetAddress, EthernetFrame, FireResult, IcmpPacket,
    IpProtocol, Ipv4Packet, Message, MessageType, OpCode,
};
use tracing_subscriber::EnvFilter;

fn main() -> FireResult<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        // Configure formatting settings.
        .with_target(true)
        .with_level(true)
        .with_ansi(true)
        .with_file(true)
        .with_line_number(true)
        // Set the subscriber as the default.
        .init();

    let args: Vec<String> = std::env::args().collect();
    let ifname = &args[1];
    let target_ip = &args[2];

    let ni = get_local_ip_addr(Some(ifname))?;
    let source_ip_addr = ni.ip_addr.into();
    let target_ip_addr = target_ip.into();

    let mut arp_req = Arp::new(
        ni.mac_addr,
        source_ip_addr,
        EthernetAddress::EMPTY,
        target_ip_addr,
        OpCode::Request,
    )?;

    let arp_reply = arp_req.send(ni)?.unwrap();
    let frame = EthernetFrame::new(
        arp_reply.source_hardware_address(),
        ni.mac_addr,
        EtherType::Ipv4,
    );

    let msg = Message::EchoRequest {
        ident: 0,
        seq_no: 1,
        data: b"hello world",
    };
    let icmp_packet = IcmpPacket::new(msg)?;
    let ip_packet = Ipv4Packet::new(
        source_ip_addr,
        target_ip_addr,
        IpProtocol::Icmp,
        icmp_packet.len(),
    );

    let icmp = icmp_packet.send(frame, ip_packet, ni.iface_index)?;
    if MessageType::EchoReply == icmp.message_type() && icmp.message_code() == 0 {
        assert_eq!(icmp.echo_data(), b"hello world");
    }

    Ok(())
}
