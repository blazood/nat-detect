use std::collections::HashMap;
use std::fmt;
use std::io::{ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::net::UdpSocket;
use std::time::Duration;

use log::{debug, info};
use stun::addr::MappedAddress;
use stun::agent::TransactionId;
use stun::attributes::{ATTR_CHANGE_REQUEST, ATTR_CHANGED_ADDRESS, ATTR_MAPPED_ADDRESS, AttrType, RawAttribute};
use stun::Error;
use stun::message::{Message, MessageClass, MessageType, METHOD_BINDING};
use crate::NatType::{FullCone, OpenInternet, PortRestrictedCone, RestrictedCone, Symmetric, SymmetricUdpFirewall};


type IoResult<T>= std::io::Result<T>;

pub(crate) const FAMILY_IPV4: u16 = 0x01;
pub(crate) const FAMILY_IPV6: u16 = 0x02;
pub(crate) const IPV4LEN: usize = 4;
pub(crate) const IPV6LEN: usize = 16;

pub const TIMEOUT: Duration = Duration::from_millis(1000);

pub const STUN_RETRY_COUNT: usize = 2;

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub enum NatType{
    UdpBlocked,
    OpenInternet,
    SymmetricUdpFirewall,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
    Unknown
}


/*
                In test I, the client sends a STUN Binding Request to a server, without any flags set in the
                CHANGE-REQUEST attribute, and without the RESPONSE-ADDRESS attribute. This causes the server
                to send the response back to the address and port that the request came from.

                In test II, the client sends a Binding Request with both the "change IP" and "change port" flags
                from the CHANGE-REQUEST attribute set.

                In test III, the client sends a Binding Request with only the "change port" flag set.

                                    +--------+
                                    |  Test  |
                                    |   I    |
                                    +--------+
                                         |
                                         |
                                         V
                                        /\              /\
                                     N /  \ Y          /  \ Y             +--------+
                      UDP     <-------/Resp\--------->/ IP \------------->|  Test  |
                      Blocked         \ ?  /          \Same/              |   II   |
                                       \  /            \? /               +--------+
                                        \/              \/                    |
                                                         | N                  |
                                                         |                    V
                                                         V                    /\
                                                     +--------+  Sym.      N /  \
                                                     |  Test  |  UDP    <---/Resp\
                                                     |   II   |  Firewall   \ ?  /
                                                     +--------+              \  /
                                                         |                    \/
                                                         V                     |Y
                              /\                         /\                    |
               Symmetric  N  /  \       +--------+   N  /  \                   V
                  NAT  <--- / IP \<-----|  Test  |<--- /Resp\               Open
                            \Same/      |   I    |     \ ?  /               Internet
                             \? /       +--------+      \  /
                              \/                         \/
                              |                           |Y
                              |                           |
                              |                           V
                              |                           Full
                              |                           Cone
                              V              /\
                          +--------+        /  \ Y
                          |  Test  |------>/Resp\---->Restricted
                          |   III  |       \ ?  /
                          +--------+        \  /
                                             \/
                                              |N
                                              |       Port
                                              +------>Restricted
*/
pub async fn nat_detect_with_servers(stun_server_list: &[&str]) -> IoResult<NatType>  {


    let mut reduce_map: HashMap<NatType, usize> = HashMap::new();
    let mut handlers = Vec::new();
    for s in stun_server_list {
        info!("{} use", s);
        let stun_server = s.to_string();
        handlers.push( tokio::spawn(async move {
            nat_detect(&stun_server).await
        }));
    }

    for h in handlers {
        let result = h.await.map_err(|_| std::io::Error::from(ErrorKind::Other))?;
        if let Result::Ok((a,n)) = result {
            info!("{} -> {:?}", a, n);
            reduce_map.entry(n.clone())
                .and_modify(|e| *e  += 1)
                .or_insert(1);
        }
        // else  if let Result::Err(e) = result{
        //     error!("{}", e);
        // }
    }

    if let Option::Some((n, _)) = reduce_map.iter().max_by(|v1, v2| v1.1.cmp(v2.1)){
        return IoResult::Ok(*n);
    }

    return other_error();
}

#[derive(Debug)]
pub struct ChangedAddress {
    pub ip: IpAddr,
    pub port: u16,
}

impl Default for ChangedAddress {
    fn default() -> Self {
        ChangedAddress {
            ip: IpAddr::V4(Ipv4Addr::from(0)),
            port: 0,
        }
    }
}

impl fmt::Display for ChangedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let family = match self.ip {
            IpAddr::V4(_) => FAMILY_IPV4,
            IpAddr::V6(_) => FAMILY_IPV6,
        };
        if family == FAMILY_IPV4 {
            write!(f, "{}:{}", self.ip, self.port)
        } else {
            write!(f, "[{}]:{}", self.ip, self.port)
        }
    }
}

impl ChangedAddress {
    /// get_from_as decodes MAPPED-ADDRESS value in message m as an attribute of type t.
    pub fn get_from_as(&mut self, m: &Message, t: AttrType) -> std::result::Result<(), Error> {
        let v = m.get(t)?;
        if v.len() <= 4 {
            return Err(Error::ErrUnexpectedEof);
        }

        let family = u16::from_be_bytes([v[0], v[1]]);
        if family != FAMILY_IPV6 && family != FAMILY_IPV4 {
            return Err(Error::Other(format!("bad value {}", family)));
        }
        self.port = u16::from_be_bytes([v[2], v[3]]);

        if family == FAMILY_IPV6 {
            let mut ip = [0; IPV6LEN];
            let l = std::cmp::min(ip.len(), v[4..].len());
            ip[..l].copy_from_slice(&v[4..4 + l]);
            self.ip = IpAddr::V6(Ipv6Addr::from(ip));
        } else {
            let mut ip = [0; IPV4LEN];
            let l = std::cmp::min(ip.len(), v[4..].len());
            ip[..l].copy_from_slice(&v[4..4 + l]);
            self.ip = IpAddr::V4(Ipv4Addr::from(ip));
        };

        Ok(())
    }

    /// add_to_as adds MAPPED-ADDRESS value to m as t attribute.
    pub fn add_to_as(&self, m: &mut Message, t: AttrType) -> std::result::Result<(), Error> {
        let family = match self.ip {
            IpAddr::V4(_) => FAMILY_IPV4,
            IpAddr::V6(_) => FAMILY_IPV6,
        };

        let mut value = vec![0u8; 4];
        //value[0] = 0 // first 8 bits are zeroes
        value[0..2].copy_from_slice(&family.to_be_bytes());
        value[2..4].copy_from_slice(&self.port.to_be_bytes());

        match self.ip {
            IpAddr::V4(ipv4) => value.extend_from_slice(&ipv4.octets()),
            IpAddr::V6(ipv6) => value.extend_from_slice(&ipv6.octets()),
        };

        m.add(t, &value);
        Ok(())
    }
}


pub async fn nat_detect(stun_server: &str) -> IoResult<(String, NatType)> {
    let transaction_id = TransactionId::new();

    let mut socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let mut_socket_ref = &mut socket;

    // test1
    let test1_message = build_request_bind_message_with_attribute(
        transaction_id, RawAttribute{
            typ: ATTR_CHANGE_REQUEST,
            value: vec![0, 0, 0, 0b0000000],
            length: 4
        }
    );
    let result = single_send(stun_server, test1_message, mut_socket_ref).await;
    debug!("[{}] test1: {}", stun_server, result.is_ok());
    if result.is_err() {
        return IoResult::Ok((stun_server.to_string(),NatType::UdpBlocked));
    }
    let test1_response: Message = result.unwrap();
    let mut mapped_address = MappedAddress::default();
    let _ = mapped_address.get_from_as(& test1_response, ATTR_MAPPED_ADDRESS);
    let test1_mapped_address = mapped_address;
    debug!("[{}] test1 mapped_address: {}", stun_server,test1_mapped_address);

    let mut changed_address = ChangedAddress::default();
    let _ = changed_address.get_from_as(& test1_response, ATTR_CHANGED_ADDRESS);
    let test1_changed_address = changed_address;
    debug!("[{}] test1 changed_address: {}", stun_server,test1_changed_address);


    // test2
    let test2_message = build_request_bind_message_with_attribute(
        transaction_id, RawAttribute{
            typ: ATTR_CHANGE_REQUEST,
            value: vec![0, 0, 0, 0b00000110],
            length: 4
        }
    );

    if mut_socket_ref.local_addr()?.ip().eq(&test1_mapped_address.ip) {
        // no nat
        let result = single_send(stun_server, test2_message, mut_socket_ref).await;
        debug!("[{}] test2: {}", stun_server,result.is_ok());
        if result.is_err() {
            return IoResult::Ok((stun_server.to_string(),OpenInternet));
        } else {
            return IoResult::Ok((stun_server.to_string(), SymmetricUdpFirewall));
        }
    } else {
        // nat
        let result = single_send(stun_server, test2_message, mut_socket_ref).await;
        debug!("[{}] test2: {}", stun_server,result.is_ok());
        if result.is_ok() {
            return IoResult::Ok((stun_server.to_string(), FullCone));
        } else {
            // test1(2)
            let test1_address = test1_changed_address.to_string();

            let result = single_send(
                test1_address.as_str(),
                build_request_bind_message(transaction_id),
                mut_socket_ref
            ).await;
            debug!("[{}] test12: {}", stun_server,result.is_ok());
            if result.is_err() {
                debug!("[{}] test12 response error!", stun_server);
                return other_error();
            } else {
                // Symmetric NAT
                let test12_response: Message = result.unwrap();
                let mut mapped_address = MappedAddress::default();
                let _ = mapped_address.get_from_as(&test12_response, ATTR_MAPPED_ADDRESS);
                let test12_mapped_address = mapped_address;
                debug!("[{}] test12 mapped_address: {}", stun_server,test12_mapped_address);

                if !mut_socket_ref.local_addr()?.ip().eq(&test12_mapped_address.ip)
                    && mut_socket_ref.local_addr()?.port() ==  test12_mapped_address.port
                {
                    return IoResult::Ok((stun_server.to_string(), Symmetric));
                } else {
                    // test 3
                    let test3_message = build_request_bind_message_with_attribute(
                        transaction_id, RawAttribute{
                            typ: ATTR_CHANGE_REQUEST,
                            value: vec![0, 0, 0, 0b00000010],
                            length: 4
                        }
                    );
                    let result = single_send(
                        test1_address.as_str(),
                        test3_message,
                        mut_socket_ref
                    ).await;
                    debug!("[{}] test3: {}", stun_server,result.is_ok());
                    if result.is_err() {
                        return IoResult::Ok((stun_server.to_string(), RestrictedCone));
                    } else {
                        return IoResult::Ok((stun_server.to_string(), PortRestrictedCone));
                    }
                }
            }
        }
    }


}

fn other_error<A>() -> IoResult<A> {
    IoResult::Err(std::io::Error::from(ErrorKind::Other))
}

fn build_request_bind_message(transaction_id: TransactionId) -> Message {
    let mut message = Message::new();
    message.transaction_id = transaction_id;
    message.typ = MessageType::new(
        METHOD_BINDING,
        MessageClass::default()
    );
    message
}

fn build_request_bind_message_with_attribute(
    transaction_id: TransactionId, a: RawAttribute
) -> Message {
    let mut message = build_request_bind_message(transaction_id);
    message.attributes.0.push(a);
    message
}

async fn single_send(stun_server: &str, mut message: Message, socket: & mut UdpSocket)
    -> IoResult<Message>
{
    message.encode();
    let bytes = message.raw;
    let mut buf = [0; 1 << 9];
    for _i in 0..STUN_RETRY_COUNT {
        match tokio::time::timeout(TIMEOUT, socket.send_to(bytes.as_slice(), stun_server)).await {
            Ok(Ok(_)) => {}
            _ => {
                continue
            }
        }
        let len = {
            match tokio::time::timeout(TIMEOUT, socket.recv_from(&mut buf)) .await {
                Ok(Ok((i, _))) => i,
                _ => {
                    continue
                }
            }
        };
        let mut result_message = Message::new();
        result_message.raw = (&buf[0..len]).to_vec();
        if result_message.decode().is_err() {
            // FIXME
            break
        }
        if message.transaction_id.eq(&result_message.transaction_id) {
            return IoResult::Ok(result_message);
        } else {
            // FIXME
            break
        }

    }
    return IoResult::Err(std::io::Error::from(ErrorKind::Other));
}

