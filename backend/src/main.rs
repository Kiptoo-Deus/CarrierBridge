use libp2p::{Swarm, PeerId};
use std::error::Error;

mod crypto;
mod messaging;
mod network;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    
    println!("SecureComm Backend Starting...");

    
    // Initialize cryptographic identity
    let identity = crypto::Identity::generate();
    println!("Node ID: {}", identity.peer_id());
    
    // Initialize network
    let mut network = network::SecureCommNetwork::new(identity).await?;
    
    println!("SecureComm backend initialized successfully");
    println!("Use Ctrl+C to shutdown");
    
    // Keep the node running
    tokio::signal::ctrl_c().await?;
    println!("Shutting down...");
    
    Ok(())
}
