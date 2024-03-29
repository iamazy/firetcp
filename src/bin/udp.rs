use firetcp::{
    get_local_ip_addr, Arp, EtherType, EthernetAddress, EthernetFrame, FireResult, IpProtocol,
    Ipv4Packet, OpCode, UdpPacket,
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
    let iface = &args[1];
    let target_ip = &args[2];

    let ni = get_local_ip_addr(Some(iface))?;

    let source_ip_addr = ni.ip_addr.into();
    let target_ip_addr = target_ip.into();

    let source_port: u16 = 42279;
    let target_port: u16 = 80;

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

    let udp_packet = UdpPacket::new(
        source_ip_addr,
        source_port,
        target_ip_addr,
        target_port,
        b"foobar",
    );

    let ip_packet = Ipv4Packet::new(
        source_ip_addr,
        target_ip_addr,
        IpProtocol::Udp,
        udp_packet.packet_len() as usize,
    );

    udp_packet.send(frame, ip_packet, ni.iface_index)
}
