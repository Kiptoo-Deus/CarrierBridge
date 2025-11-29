use libp2p::{
    identity, noise, tcp, yamux, 
    swarm::{Swarm, SwarmEvent},
    PeerId, Transport,
};
use std::error::Error;
use crate::crypto::Identity;

pub struct SecureCommNetwork {
    pub swarm: Swarm<SecureCommBehaviour>,
    pub peer_id: PeerId,
}

impl SecureCommNetwork {
    pub async fn new(identity: Identity) -> Result<Self, Box<dyn Error>> {
        let peer_id = identity.peer_id();
        let keypair = identity.keypair().clone();
        
        // Create transport with encryption and multiplexing
        let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise::Config::new(&keypair)?)
            .multiplex(yamux::Config::default())
            .boxed();

        // Create behaviour
        let behaviour = SecureCommBehaviour::new(keypair.public()).await?;
        
        // Create swarm
        let swarm = Swarm::with_tokio_executor(transport, behaviour, peer_id);
        
        Ok(SecureCommNetwork {
            swarm,
            peer_id,
        })
    }
    
    pub async fn start_listening(&mut self, addr: &str) -> Result<(), Box<dyn Error>> {
        let listen_addr: libp2p::Multiaddr = addr.parse()?;
        self.swarm.listen_on(listen_addr)?;
        println!("Listening on: {}", addr);
        Ok(())
    }
    
    pub async fn run_event_loop(&mut self) {
        println!("Starting network event loop...");
        
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!(" Now listening on: {}", address);
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("Connected to: {}", peer_id);
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    println!("Disconnected from: {}", peer_id);
                }
                SwarmEvent::Behaviour(event) => {
                    println!("Behaviour event: {:?}", event);
                }
                _ => {}
            }
        }
    }
}


use libp2p::swarm::NetworkBehaviour;

#[derive(NetworkBehaviour)]
pub struct SecureCommBehaviour {
   
    identify: libp2p::identify::Behaviour,
}

impl SecureCommBehaviour {
    pub async fn new(local_public_key: identity::PublicKey) -> Result<Self, Box<dyn Error>> {
        let identify = libp2p::identify::Behaviour::new(
            libp2p::identify::Config::new("/securecomm/1.0.0".to_string(), local_public_key)
        );
        
        Ok(SecureCommBehaviour {
            identify,
        })
    }
}
