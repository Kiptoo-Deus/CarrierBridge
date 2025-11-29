#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Identity;

    #[tokio::test]
    async fn test_network_initialization() {
        let identity = Identity::generate();
        let network = network::SecureCommNetwork::new(identity).await;
        
        assert!(network.is_ok());
        let network = network.unwrap();
        assert!(!network.peer_id.to_string().is_empty());
    }
    
    #[tokio::test] 
    async fn test_listening() {
        let identity = Identity::generate();
        let mut network = network::SecureCommNetwork::new(identity).await.unwrap();
        
        let result = network.start_listening("/ip4/127.0.0.1/tcp/0").await;
        assert!(result.is_ok());
    }
}
