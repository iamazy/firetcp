use firetcp::{Arp, EthernetAddress, FireResult, OpCode};
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

    let ni = firetcp::get_local_ip_addr(Some(iface))?;

    let mut arp_req = Arp::new(
        ni.mac_addr,
        ni.ip_addr.into(),
        EthernetAddress::BROADCAST,
        target_ip.into(),
        OpCode::Request,
    )?;

    let _ = arp_req.send(ni);

    Ok(())
}
