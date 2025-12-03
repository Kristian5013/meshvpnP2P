//! Multi-region synchronization for exit nodes using AWS services
//!
//! Uses DynamoDB for node registration and health status,
//! and S3 for log storage and metrics.
//!
//! This module requires the "aws" feature to be enabled.

use std::time::Duration;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::config::SyncConfig;
use crate::error::{ExitError, ExitResult};

/// Exit node status for synchronization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitNodeStatus {
    /// Node identifier
    pub node_id: String,
    /// AWS Region
    pub region: String,
    /// Public IP address
    pub public_ip: String,
    /// Private IP address
    pub private_ip: String,
    /// EC2 instance ID
    pub instance_id: String,
    /// Current load (0-100)
    pub load: u8,
    /// Active connections
    pub connections: u32,
    /// Bytes per second throughput
    pub bandwidth_bps: u64,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Last heartbeat timestamp (Unix)
    pub last_heartbeat: i64,
    /// Node version
    pub version: String,
    /// Is healthy
    pub healthy: bool,
    /// Start time
    pub started_at: i64,
    /// Supported protocols
    pub protocols: Vec<String>,
}

impl Default for ExitNodeStatus {
    fn default() -> Self {
        let now = Utc::now().timestamp();
        Self {
            node_id: String::new(),
            region: String::new(),
            public_ip: String::new(),
            private_ip: String::new(),
            instance_id: String::new(),
            load: 0,
            connections: 0,
            bandwidth_bps: 0,
            bytes_transferred: 0,
            last_heartbeat: now,
            version: env!("CARGO_PKG_VERSION").to_string(),
            healthy: true,
            started_at: now,
            protocols: vec!["meshvpn/1.0".to_string()],
        }
    }
}

/// Node metrics for detailed monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub timestamp: i64,
    pub node_id: String,
    pub region: String,
    pub cpu_percent: f32,
    pub memory_percent: f32,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub active_circuits: u32,
    pub packets_per_second: u64,
    pub avg_latency_ms: f32,
    pub error_count: u64,
}

// ============================================================================
// AWS Feature Implementation
// ============================================================================

#[cfg(feature = "aws")]
mod aws_impl {
    use super::*;
    use std::collections::HashMap;
    use aws_config::BehaviorVersion;
    use aws_sdk_dynamodb::types::{AttributeValue, KeyType, ScalarAttributeType};
    use aws_sdk_dynamodb::Client as DynamoClient;
    use aws_sdk_s3::Client as S3Client;
    use aws_sdk_s3::primitives::ByteStream;
    use tracing::{debug, error, info};

    /// EC2 instance metadata
    #[derive(Debug, Clone)]
    pub struct Ec2Metadata {
        pub instance_id: String,
        pub region: String,
        pub availability_zone: String,
        pub public_ip: String,
        pub private_ip: String,
        pub instance_type: String,
    }

    /// Region synchronization service using AWS
    pub struct RegionSync {
        node_id: String,
        region: String,
        dynamo: DynamoClient,
        s3: S3Client,
        table_name: String,
        s3_bucket: String,
        interval: Duration,
        status: ExitNodeStatus,
    }

    impl RegionSync {
        pub async fn new(config: &SyncConfig) -> ExitResult<Self> {
            info!("Initializing AWS SDK for region: {}", config.aws_region);

            let aws_config = aws_config::defaults(BehaviorVersion::latest())
                .region(aws_config::Region::new(config.aws_region.clone()))
                .load()
                .await;

            let dynamo = DynamoClient::new(&aws_config);
            let s3 = S3Client::new(&aws_config);

            let metadata = get_ec2_metadata().await?;
            let node_id = generate_node_id(&metadata.instance_id);

            let mut status = ExitNodeStatus::default();
            status.node_id = node_id.clone();
            status.region = config.aws_region.clone();
            status.instance_id = metadata.instance_id;
            status.public_ip = metadata.public_ip;
            status.private_ip = metadata.private_ip;

            let table_name = config.dynamodb_table.clone()
                .unwrap_or_else(|| "meshvpn-exit-nodes".to_string());
            let s3_bucket = config.s3_bucket.clone()
                .unwrap_or_else(|| "meshvpn-logs".to_string());

            Ok(Self {
                node_id,
                region: config.aws_region.clone(),
                dynamo,
                s3,
                table_name,
                s3_bucket,
                interval: Duration::from_secs(config.interval_secs),
                status,
            })
        }

        pub async fn ensure_table(&self) -> ExitResult<()> {
            match self.dynamo.describe_table()
                .table_name(&self.table_name)
                .send()
                .await
            {
                Ok(_) => {
                    info!("DynamoDB table '{}' exists", self.table_name);
                    return Ok(());
                }
                Err(e) => {
                    if !e.to_string().contains("ResourceNotFoundException") {
                        return Err(ExitError::AwsError(format!("Failed to describe table: {}", e)));
                    }
                }
            }

            info!("Creating DynamoDB table '{}'", self.table_name);

            self.dynamo.create_table()
                .table_name(&self.table_name)
                .attribute_definitions(
                    aws_sdk_dynamodb::types::AttributeDefinition::builder()
                        .attribute_name("node_id")
                        .attribute_type(ScalarAttributeType::S)
                        .build()
                        .map_err(|e| ExitError::AwsError(e.to_string()))?
                )
                .attribute_definitions(
                    aws_sdk_dynamodb::types::AttributeDefinition::builder()
                        .attribute_name("region")
                        .attribute_type(ScalarAttributeType::S)
                        .build()
                        .map_err(|e| ExitError::AwsError(e.to_string()))?
                )
                .key_schema(
                    aws_sdk_dynamodb::types::KeySchemaElement::builder()
                        .attribute_name("node_id")
                        .key_type(KeyType::Hash)
                        .build()
                        .map_err(|e| ExitError::AwsError(e.to_string()))?
                )
                .global_secondary_indexes(
                    aws_sdk_dynamodb::types::GlobalSecondaryIndex::builder()
                        .index_name("region-index")
                        .key_schema(
                            aws_sdk_dynamodb::types::KeySchemaElement::builder()
                                .attribute_name("region")
                                .key_type(KeyType::Hash)
                                .build()
                                .map_err(|e| ExitError::AwsError(e.to_string()))?
                        )
                        .projection(
                            aws_sdk_dynamodb::types::Projection::builder()
                                .projection_type(aws_sdk_dynamodb::types::ProjectionType::All)
                                .build()
                        )
                        .provisioned_throughput(
                            aws_sdk_dynamodb::types::ProvisionedThroughput::builder()
                                .read_capacity_units(5)
                                .write_capacity_units(5)
                                .build()
                                .map_err(|e| ExitError::AwsError(e.to_string()))?
                        )
                        .build()
                        .map_err(|e| ExitError::AwsError(e.to_string()))?
                )
                .provisioned_throughput(
                    aws_sdk_dynamodb::types::ProvisionedThroughput::builder()
                        .read_capacity_units(5)
                        .write_capacity_units(5)
                        .build()
                        .map_err(|e| ExitError::AwsError(e.to_string()))?
                )
                .send()
                .await
                .map_err(|e| ExitError::AwsError(format!("Failed to create table: {}", e)))?;

            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;

                let resp = self.dynamo.describe_table()
                    .table_name(&self.table_name)
                    .send()
                    .await
                    .map_err(|e| ExitError::AwsError(format!("Failed to describe table: {}", e)))?;

                if let Some(table) = resp.table() {
                    if table.table_status() == Some(&aws_sdk_dynamodb::types::TableStatus::Active) {
                        info!("DynamoDB table '{}' is now active", self.table_name);
                        break;
                    }
                }
            }

            Ok(())
        }

        pub async fn start(&self) -> ExitResult<()> {
            info!("Starting region sync for node: {}", self.node_id);
            self.ensure_table().await?;
            self.register().await?;
            Ok(())
        }

        pub async fn register(&self) -> ExitResult<()> {
            info!("Registering node {} in region {}", self.node_id, self.region);

            let item = self.status_to_item(&self.status);

            self.dynamo.put_item()
                .table_name(&self.table_name)
                .set_item(Some(item))
                .send()
                .await
                .map_err(|e| ExitError::AwsError(format!("Failed to register node: {}", e)))?;

            info!("Node {} registered successfully", self.node_id);
            Ok(())
        }

        pub async fn heartbeat(&mut self, status: ExitNodeStatus) -> ExitResult<()> {
            self.status = status.clone();
            self.status.last_heartbeat = Utc::now().timestamp();

            let item = self.status_to_item(&self.status);

            self.dynamo.put_item()
                .table_name(&self.table_name)
                .set_item(Some(item))
                .send()
                .await
                .map_err(|e| ExitError::AwsError(format!("Failed to update heartbeat: {}", e)))?;

            debug!("Heartbeat for node {}: load={}%, connections={}",
                self.node_id, self.status.load, self.status.connections);

            Ok(())
        }

        pub async fn get_nodes(&self, region: &str) -> ExitResult<Vec<ExitNodeStatus>> {
            let result = self.dynamo.query()
                .table_name(&self.table_name)
                .index_name("region-index")
                .key_condition_expression("region = :region")
                .expression_attribute_values(":region", AttributeValue::S(region.to_string()))
                .send()
                .await
                .map_err(|e| ExitError::AwsError(format!("Failed to query nodes: {}", e)))?;

            let mut nodes = Vec::new();
            for item in result.items() {
                if let Some(status) = self.item_to_status(item) {
                    nodes.push(status);
                }
            }

            Ok(nodes)
        }

        pub async fn get_all_healthy_nodes(&self) -> ExitResult<Vec<ExitNodeStatus>> {
            let result = self.dynamo.scan()
                .table_name(&self.table_name)
                .filter_expression("healthy = :healthy")
                .expression_attribute_values(":healthy", AttributeValue::Bool(true))
                .send()
                .await
                .map_err(|e| ExitError::AwsError(format!("Failed to scan nodes: {}", e)))?;

            let mut nodes = Vec::new();
            let now = Utc::now().timestamp();
            let stale_threshold = 60;

            for item in result.items() {
                if let Some(status) = self.item_to_status(item) {
                    if now - status.last_heartbeat < stale_threshold {
                        nodes.push(status);
                    }
                }
            }

            Ok(nodes)
        }

        pub async fn upload_logs(&self, log_data: &[u8], log_name: &str) -> ExitResult<String> {
            let timestamp = Utc::now().format("%Y/%m/%d/%H");
            let key = format!("{}/{}/{}/{}", self.region, self.node_id, timestamp, log_name);

            info!("Uploading logs to s3://{}/{}", self.s3_bucket, key);

            let body = ByteStream::from(log_data.to_vec());

            self.s3.put_object()
                .bucket(&self.s3_bucket)
                .key(&key)
                .body(body)
                .content_type("application/gzip")
                .send()
                .await
                .map_err(|e| ExitError::AwsError(format!("Failed to upload logs: {}", e)))?;

            let s3_uri = format!("s3://{}/{}", self.s3_bucket, key);
            info!("Logs uploaded to {}", s3_uri);

            Ok(s3_uri)
        }

        pub async fn upload_metrics(&self, metrics: &NodeMetrics) -> ExitResult<String> {
            let timestamp = Utc::now().format("%Y/%m/%d/%H%M%S");
            let key = format!("metrics/{}/{}/{}.json", self.region, self.node_id, timestamp);

            let json = serde_json::to_vec(metrics)
                .map_err(|e| ExitError::ConfigError(format!("Failed to serialize metrics: {}", e)))?;

            let body = ByteStream::from(json);

            self.s3.put_object()
                .bucket(&self.s3_bucket)
                .key(&key)
                .body(body)
                .content_type("application/json")
                .send()
                .await
                .map_err(|e| ExitError::AwsError(format!("Failed to upload metrics: {}", e)))?;

            Ok(format!("s3://{}/{}", self.s3_bucket, key))
        }

        pub async fn deregister(&self) -> ExitResult<()> {
            info!("Deregistering node {}", self.node_id);

            self.dynamo.delete_item()
                .table_name(&self.table_name)
                .key("node_id", AttributeValue::S(self.node_id.clone()))
                .send()
                .await
                .map_err(|e| ExitError::AwsError(format!("Failed to deregister node: {}", e)))?;

            info!("Node {} deregistered", self.node_id);
            Ok(())
        }

        pub fn interval(&self) -> Duration {
            self.interval
        }

        pub fn node_id(&self) -> &str {
            &self.node_id
        }

        pub fn status(&self) -> &ExitNodeStatus {
            &self.status
        }

        fn status_to_item(&self, status: &ExitNodeStatus) -> HashMap<String, AttributeValue> {
            let mut item = HashMap::new();
            item.insert("node_id".to_string(), AttributeValue::S(status.node_id.clone()));
            item.insert("region".to_string(), AttributeValue::S(status.region.clone()));
            item.insert("public_ip".to_string(), AttributeValue::S(status.public_ip.clone()));
            item.insert("private_ip".to_string(), AttributeValue::S(status.private_ip.clone()));
            item.insert("instance_id".to_string(), AttributeValue::S(status.instance_id.clone()));
            item.insert("load".to_string(), AttributeValue::N(status.load.to_string()));
            item.insert("connections".to_string(), AttributeValue::N(status.connections.to_string()));
            item.insert("bandwidth_bps".to_string(), AttributeValue::N(status.bandwidth_bps.to_string()));
            item.insert("bytes_transferred".to_string(), AttributeValue::N(status.bytes_transferred.to_string()));
            item.insert("last_heartbeat".to_string(), AttributeValue::N(status.last_heartbeat.to_string()));
            item.insert("version".to_string(), AttributeValue::S(status.version.clone()));
            item.insert("healthy".to_string(), AttributeValue::Bool(status.healthy));
            item.insert("started_at".to_string(), AttributeValue::N(status.started_at.to_string()));
            item.insert("protocols".to_string(), AttributeValue::L(
                status.protocols.iter().map(|p| AttributeValue::S(p.clone())).collect()
            ));
            item
        }

        fn item_to_status(&self, item: &HashMap<String, AttributeValue>) -> Option<ExitNodeStatus> {
            Some(ExitNodeStatus {
                node_id: item.get("node_id")?.as_s().ok()?.clone(),
                region: item.get("region")?.as_s().ok()?.clone(),
                public_ip: item.get("public_ip")?.as_s().ok()?.clone(),
                private_ip: item.get("private_ip").and_then(|v| v.as_s().ok()).cloned().unwrap_or_default(),
                instance_id: item.get("instance_id").and_then(|v| v.as_s().ok()).cloned().unwrap_or_default(),
                load: item.get("load").and_then(|v| v.as_n().ok()).and_then(|n| n.parse().ok()).unwrap_or(0),
                connections: item.get("connections").and_then(|v| v.as_n().ok()).and_then(|n| n.parse().ok()).unwrap_or(0),
                bandwidth_bps: item.get("bandwidth_bps").and_then(|v| v.as_n().ok()).and_then(|n| n.parse().ok()).unwrap_or(0),
                bytes_transferred: item.get("bytes_transferred").and_then(|v| v.as_n().ok()).and_then(|n| n.parse().ok()).unwrap_or(0),
                last_heartbeat: item.get("last_heartbeat").and_then(|v| v.as_n().ok()).and_then(|n| n.parse().ok()).unwrap_or(0),
                version: item.get("version").and_then(|v| v.as_s().ok()).cloned().unwrap_or_default(),
                healthy: item.get("healthy").and_then(|v| v.as_bool().ok()).copied().unwrap_or(false),
                started_at: item.get("started_at").and_then(|v| v.as_n().ok()).and_then(|n| n.parse().ok()).unwrap_or(0),
                protocols: item.get("protocols")
                    .and_then(|v| v.as_l().ok())
                    .map(|l| l.iter().filter_map(|v| v.as_s().ok().cloned()).collect())
                    .unwrap_or_default(),
            })
        }
    }

    /// Get EC2 instance metadata using IMDSv2
    pub async fn get_ec2_metadata() -> ExitResult<Ec2Metadata> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| ExitError::NetworkError(e.to_string()))?;

        let token = client.put("http://169.254.169.254/latest/api/token")
            .header("X-aws-ec2-metadata-token-ttl-seconds", "300")
            .send()
            .await
            .map_err(|e| ExitError::NetworkError(format!("Failed to get IMDS token: {}", e)))?
            .text()
            .await
            .map_err(|e| ExitError::NetworkError(format!("Failed to read IMDS token: {}", e)))?;

        let get_metadata = |path: &str| {
            let client = client.clone();
            let token = token.clone();
            let path = path.to_string();
            async move {
                client.get(format!("http://169.254.169.254/latest/meta-data/{}", path))
                    .header("X-aws-ec2-metadata-token", &token)
                    .send()
                    .await
                    .map_err(|e| ExitError::NetworkError(format!("Failed to get {}: {}", path, e)))?
                    .text()
                    .await
                    .map_err(|e| ExitError::NetworkError(format!("Failed to read {}: {}", path, e)))
            }
        };

        let instance_id = get_metadata("instance-id").await?;
        let availability_zone = get_metadata("placement/availability-zone").await?;
        let region = availability_zone.trim_end_matches(|c: char| c.is_alphabetic()).to_string();
        let instance_type = get_metadata("instance-type").await?;
        let public_ip = get_metadata("public-ipv4").await.unwrap_or_default();
        let private_ip = get_metadata("local-ipv4").await?;

        Ok(Ec2Metadata {
            instance_id,
            region,
            availability_zone,
            public_ip,
            private_ip,
            instance_type,
        })
    }

    fn generate_node_id(instance_id: &str) -> String {
        format!("exit-{}", instance_id.trim_start_matches("i-"))
    }

    pub async fn run_sync_task(sync: std::sync::Arc<tokio::sync::RwLock<RegionSync>>) {
        let interval = {
            let sync = sync.read().await;
            sync.interval()
        };

        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;

            let mut sync = sync.write().await;
            let status = sync.status().clone();

            if let Err(e) = sync.heartbeat(status).await {
                error!("Failed to send heartbeat: {}", e);
            }
        }
    }
}

// ============================================================================
// Stub Implementation (when AWS feature is disabled)
// ============================================================================

#[cfg(not(feature = "aws"))]
mod stub_impl {
    use super::*;
    use tracing::warn;

    /// Stub RegionSync when AWS is not enabled
    pub struct RegionSync {
        interval: Duration,
        status: ExitNodeStatus,
    }

    impl RegionSync {
        pub async fn new(config: &SyncConfig) -> ExitResult<Self> {
            warn!("AWS feature not enabled, RegionSync is a stub");
            Ok(Self {
                interval: Duration::from_secs(config.interval_secs),
                status: ExitNodeStatus::default(),
            })
        }

        pub async fn start(&self) -> ExitResult<()> {
            warn!("RegionSync::start called but AWS feature not enabled");
            Ok(())
        }

        pub async fn heartbeat(&mut self, _status: ExitNodeStatus) -> ExitResult<()> {
            Ok(())
        }

        pub async fn get_nodes(&self, _region: &str) -> ExitResult<Vec<ExitNodeStatus>> {
            Ok(Vec::new())
        }

        pub async fn get_all_healthy_nodes(&self) -> ExitResult<Vec<ExitNodeStatus>> {
            Ok(Vec::new())
        }

        pub async fn deregister(&self) -> ExitResult<()> {
            Ok(())
        }

        pub fn interval(&self) -> Duration {
            self.interval
        }

        pub fn status(&self) -> &ExitNodeStatus {
            &self.status
        }
    }
}

// Re-export the appropriate implementation
#[cfg(feature = "aws")]
pub use aws_impl::*;

#[cfg(not(feature = "aws"))]
pub use stub_impl::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_default() {
        let status = ExitNodeStatus::default();
        assert!(status.healthy);
        assert_eq!(status.load, 0);
        assert!(!status.version.is_empty());
    }
}
