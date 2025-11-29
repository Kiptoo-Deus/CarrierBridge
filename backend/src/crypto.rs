use libp2p::identity::{Keypair, PeerId};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key generation failed")]
    KeyGenerationFailed,
    #[error("Signature verification failed")]
    InvalidSignature,
}

pub struct Identity {
    keypair: Keypair,
}

impl Identity {
    pub fn generate() -> Self {
        let keypair = Keypair::generate_ed25519();
        Identity { keypair }
    }
    
    pub fn peer_id(&self) -> PeerId {
        PeerId::from(self.keypair.public())
    }
    
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = Identity::generate();
        let peer_id = identity.peer_id();
        
        assert!(!peer_id.to_string().is_empty());
        println!("Generated PeerId: {}", peer_id);
    }
}
