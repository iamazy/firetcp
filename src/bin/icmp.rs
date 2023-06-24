use firetcp::{
    get_local_ip_addr, Arp, EtherType, EthernetAddress, EthernetFrame, FireResult, Icmp, IpPacket,
    IpProtocol, Message,
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

    let frame = EthernetFrame::new(EthernetAddress::BROADCAST, ni.mac_addr, EtherType::Arp);
    let arp_req = Arp::new(frame.source_mac_address(), source_ip_addr, target_ip_addr)?;

    let arp_reply = arp_req.send(frame, ni.iface_index)?.unwrap();
    let frame = EthernetFrame::new(
        arp_reply.source_hardware_address(),
        ni.mac_addr,
        EtherType::Ipv4,
    );

    let msg = Message::EchoRequest {
        ident: 0,
        seq_no: 1,
        data: "hello world".as_bytes(),
    };
    let icmp_packet = Icmp::new(msg)?;
    let ip_packet = IpPacket::new(
        source_ip_addr,
        target_ip_addr,
        IpProtocol::Icmp,
        icmp_packet.len(),
    );

    let _ = icmp_packet.send(frame, ip_packet, ni.iface_index)?;

    Ok(())
}
