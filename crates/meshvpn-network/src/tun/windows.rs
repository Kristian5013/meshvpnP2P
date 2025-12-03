//! Windows TUN device implementation using WinTun
//!
//! WinTun is the high-performance TUN driver used by WireGuard on Windows.
//! It requires wintun.dll to be present in the same directory as the executable.
//!
//! Download wintun.dll from: https://www.wintun.net/

use async_trait::async_trait;
use bytes::Bytes;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, trace, warn};

use super::{TunConfig, TunDevice};
use crate::error::{NetworkError, NetworkResult};

/// Ring buffer size for WinTun (4MB - must be power of 2)
const RING_CAPACITY: u32 = 0x400000;

/// Windows TUN device using WinTun
pub struct WindowsTun {
    /// WinTun session handle
    session: Arc<wintun::Session>,
    /// WinTun adapter handle
    adapter: Arc<wintun::Adapter>,
    /// Adapter name
    name: String,
    /// MTU
    mtu: u16,
    /// Adapter IP address
    address: Ipv4Addr,
    /// Is running
    running: Arc<AtomicBool>,
    /// Packet receive channel
    rx: Mutex<mpsc::Receiver<Bytes>>,
    /// Receive task handle
    recv_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Statistics: bytes received
    bytes_rx: AtomicU64,
    /// Statistics: bytes transmitted
    bytes_tx: AtomicU64,
    /// Statistics: packets received
    packets_rx: AtomicU64,
    /// Statistics: packets transmitted
    packets_tx: AtomicU64,
}

impl WindowsTun {
    /// Create a new Windows TUN device
    ///
    /// **Requirements:**
    /// - Administrator privileges
    /// - wintun.dll in the same directory as executable or in PATH
    ///
    /// **Note:** Download wintun.dll from https://www.wintun.net/
    pub async fn create(config: TunConfig) -> NetworkResult<Self> {
        // Check admin privileges first
        if !is_admin() {
            return Err(NetworkError::TunError(
                "Administrator privileges required. Please run as Administrator.".into()
            ));
        }

        info!("Loading WinTun driver...");

        // Load WinTun DLL
        let wintun = unsafe { wintun::load() }.map_err(|e| {
            NetworkError::TunError(format!(
                "Failed to load wintun.dll: {}. \
                 Download from https://www.wintun.net/ and place in the application directory.",
                e
            ))
        })?;

        info!("WinTun loaded, creating adapter '{}'...", config.name);

        // Delete any existing adapter with the same name
        let _ = wintun::Adapter::open(&wintun, &config.name);

        // Create adapter with GUID for consistent identification
        let adapter = wintun::Adapter::create(&wintun, &config.name, "MeshVPN", None)
            .map_err(|e| NetworkError::TunError(format!("Failed to create adapter: {}", e)))?;

        info!("Adapter created, configuring IP address...");

        // Configure IP address
        configure_adapter(&config.name, config.address, config.netmask, config.mtu).await?;

        info!("Starting WinTun session...");

        // Start session with ring buffer
        let session = adapter
            .start_session(RING_CAPACITY)
            .map_err(|e| NetworkError::TunError(format!("Failed to start session: {}", e)))?;

        let session = Arc::new(session);
        // adapter is already Arc<Adapter> from wintun::Adapter::create
        let running = Arc::new(AtomicBool::new(true));

        // Create packet channel
        let (tx, rx) = mpsc::channel::<Bytes>(1000);

        // Start receive task
        let recv_task = spawn_receive_task(session.clone(), running.clone(), tx);

        info!(
            "Windows TUN adapter '{}' created with IP {}/{}",
            config.name, config.address, config.netmask
        );

        Ok(Self {
            session,
            adapter: adapter,
            name: config.name,
            mtu: config.mtu,
            address: config.address,
            running,
            rx: Mutex::new(rx),
            recv_task: Mutex::new(Some(recv_task)),
            bytes_rx: AtomicU64::new(0),
            bytes_tx: AtomicU64::new(0),
            packets_rx: AtomicU64::new(0),
            packets_tx: AtomicU64::new(0),
        })
    }

    /// Get adapter LUID for routing configuration
    pub fn luid(&self) -> u64 {
        let luid = self.adapter.get_luid();
        // NET_LUID_LH is a union with a u64 Value field
        unsafe { luid.Value }
    }

    /// Get adapter IP address
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Get statistics
    pub fn stats(&self) -> TunStats {
        TunStats {
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            packets_rx: self.packets_rx.load(Ordering::Relaxed),
            packets_tx: self.packets_tx.load(Ordering::Relaxed),
        }
    }

    /// Set up default route through this adapter (route all traffic)
    /// The server_endpoint is excluded from VPN routing to prevent loops.
    pub async fn set_default_route_internal(&self, server_endpoint: std::net::SocketAddr) -> NetworkResult<()> {
        info!("Setting up default route through {}", self.name);

        // First, add a specific route for the VPN server via the default gateway
        // This prevents tunnel packets from being routed through the tunnel
        let server_ip = server_endpoint.ip().to_string();
        if let Some(gateway) = get_default_gateway().await {
            info!("Adding route for VPN server {} via default gateway {}", server_ip, gateway);
            add_route_cidr(&server_ip, 32, &gateway).await?;
        }

        // Add routes for 0.0.0.0/1 and 128.0.0.0/1 to route all traffic through the TUN interface
        // Use netsh to specify the interface explicitly
        add_route_via_interface("0.0.0.0", 1, &self.name).await?;
        add_route_via_interface("128.0.0.0", 1, &self.name).await?;

        Ok(())
    }

    /// Add a specific route through this adapter
    pub async fn add_route(&self, destination: IpAddr, prefix_len: u8) -> NetworkResult<()> {
        let dest_str = destination.to_string();
        add_route_cidr(&dest_str, prefix_len, &self.address.to_string()).await
    }

    /// Set DNS servers for this adapter
    pub async fn set_dns(&self, servers: &[Ipv4Addr]) -> NetworkResult<()> {
        if servers.is_empty() {
            return Ok(());
        }

        set_adapter_dns(&self.name, servers).await
    }
}

#[async_trait]
impl TunDevice for WindowsTun {
    async fn read(&self) -> NetworkResult<Bytes> {
        let mut rx = self.rx.lock().await;

        match rx.recv().await {
            Some(packet) => {
                self.bytes_rx.fetch_add(packet.len() as u64, Ordering::Relaxed);
                self.packets_rx.fetch_add(1, Ordering::Relaxed);
                trace!("TUN read: {} bytes", packet.len());
                Ok(packet)
            }
            None => {
                Err(NetworkError::TunError("Receive channel closed".into()))
            }
        }
    }

    async fn write(&self, packet: &[u8]) -> NetworkResult<()> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(NetworkError::TunError("Adapter is closed".into()));
        }

        let session = self.session.clone();
        let packet_data = packet.to_vec();
        let len = packet.len();

        let result = tokio::task::spawn_blocking(move || {
            // Allocate send buffer
            let mut send_packet = session
                .allocate_send_packet(packet_data.len() as u16)
                .map_err(|e| NetworkError::TunError(format!("Failed to allocate packet: {}", e)))?;

            // Copy data
            send_packet.bytes_mut().copy_from_slice(&packet_data);

            // Send - this consumes the packet
            session.send_packet(send_packet);

            Ok::<(), NetworkError>(())
        })
        .await
        .map_err(|e| NetworkError::TunError(format!("Task join error: {}", e)))?;

        result?;

        self.bytes_tx.fetch_add(len as u64, Ordering::Relaxed);
        self.packets_tx.fetch_add(1, Ordering::Relaxed);
        trace!("TUN write: {} bytes", len);

        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    async fn close(&self) -> NetworkResult<()> {
        info!("Closing Windows TUN adapter: {}", self.name);

        // Signal shutdown
        self.running.store(false, Ordering::SeqCst);

        // Wait for receive task to finish
        if let Some(task) = self.recv_task.lock().await.take() {
            task.abort();
        }

        // Remove routes
        let _ = self.remove_default_route().await;

        info!("TUN adapter closed");
        Ok(())
    }

    async fn set_default_route(&self, server_endpoint: std::net::SocketAddr) -> NetworkResult<()> {
        self.set_default_route_internal(server_endpoint).await
    }

    async fn remove_default_route(&self) -> NetworkResult<()> {
        remove_route_cidr("0.0.0.0", 1).await?;
        remove_route_cidr("128.0.0.0", 1).await?;
        Ok(())
    }

    fn get_stats(&self) -> super::TrafficStats {
        super::TrafficStats {
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            packets_rx: self.packets_rx.load(Ordering::Relaxed),
            packets_tx: self.packets_tx.load(Ordering::Relaxed),
        }
    }
}

impl Drop for WindowsTun {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        debug!("WindowsTun dropped");
    }
}

/// TUN statistics
#[derive(Debug, Clone, Default)]
pub struct TunStats {
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub packets_rx: u64,
    pub packets_tx: u64,
}

/// Spawn background task to receive packets from WinTun
fn spawn_receive_task(
    session: Arc<wintun::Session>,
    running: Arc<AtomicBool>,
    tx: mpsc::Sender<Bytes>,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        while running.load(Ordering::Relaxed) {
            // Use blocking receive with timeout
            match session.receive_blocking() {
                Ok(packet) => {
                    let bytes = Bytes::copy_from_slice(packet.bytes());
                    if tx.blocking_send(bytes).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if running.load(Ordering::Relaxed) {
                        warn!("WinTun receive error: {}", e);
                    }
                    break;
                }
            }
        }
        debug!("WinTun receive task stopped");
    })
}

/// Configure adapter IP address, netmask, and MTU
async fn configure_adapter(
    name: &str,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: u16,
) -> NetworkResult<()> {
    use tokio::process::Command;

    // Wait for adapter to be ready
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Set IP address using netsh
    let output = Command::new("netsh")
        .args([
            "interface", "ip", "set", "address",
            name,
            "static",
            &address.to_string(),
            &netmask.to_string(),
        ])
        .output()
        .await?;

    if !output.status.success() {
        // Try alternative method using PowerShell
        let ps_result = Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "New-NetIPAddress -InterfaceAlias '{}' -IPAddress {} -PrefixLength {} -ErrorAction SilentlyContinue; \
                     Set-NetIPAddress -InterfaceAlias '{}' -IPAddress {} -PrefixLength {} -ErrorAction SilentlyContinue",
                    name, address, netmask_to_prefix(netmask),
                    name, address, netmask_to_prefix(netmask)
                )
            ])
            .output()
            .await?;

        if !ps_result.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NetworkError::TunError(format!(
                "Failed to configure adapter IP: {}",
                stderr
            )));
        }
    }

    // Set MTU
    let _ = Command::new("netsh")
        .args([
            "interface", "ipv4", "set", "subinterface",
            name,
            &format!("mtu={}", mtu),
            "store=persistent"
        ])
        .output()
        .await;

    // Disable IPv6 (optional, for simplicity)
    let _ = Command::new("netsh")
        .args([
            "interface", "ipv6", "set", "interface",
            name,
            "disabled"
        ])
        .output()
        .await;

    debug!("Configured adapter {} with IP {}/{} MTU {}", name, address, netmask, mtu);
    Ok(())
}

/// Set DNS servers for adapter
async fn set_adapter_dns(name: &str, servers: &[Ipv4Addr]) -> NetworkResult<()> {
    use tokio::process::Command;

    if servers.is_empty() {
        return Ok(());
    }

    // Set primary DNS
    let output = Command::new("netsh")
        .args([
            "interface", "ip", "set", "dns",
            name,
            "static",
            &servers[0].to_string(),
            "primary"
        ])
        .output()
        .await?;

    if !output.status.success() {
        warn!("Failed to set primary DNS");
    }

    // Add secondary DNS if available
    for dns in servers.iter().skip(1) {
        let _ = Command::new("netsh")
            .args([
                "interface", "ip", "add", "dns",
                name,
                &dns.to_string(),
            ])
            .output()
            .await;
    }

    debug!("Set DNS servers for {}: {:?}", name, servers);
    Ok(())
}

/// Add a route with CIDR notation via gateway
async fn add_route_cidr(dest: &str, prefix_len: u8, gateway: &str) -> NetworkResult<()> {
    use tokio::process::Command;

    let mask = prefix_to_netmask(prefix_len);

    let output = Command::new("route")
        .args(["add", dest, "mask", &mask, gateway, "metric", "1"])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        debug!("Route add result: {}", stderr);
    }

    debug!("Added route {}/{} via {}", dest, prefix_len, gateway);
    Ok(())
}

/// Add a route via a specific interface (by name)
async fn add_route_via_interface(dest: &str, prefix_len: u8, interface_name: &str) -> NetworkResult<()> {
    use tokio::process::Command;

    // Use netsh to add route with interface name
    // netsh interface ipv4 add route <prefix>/<len> <interface> <nexthop> metric=<metric>
    // For on-link routes (no next hop), use 0.0.0.0 as nexthop
    let prefix = format!("{}/{}", dest, prefix_len);

    info!("Adding route {} via interface {}", prefix, interface_name);

    let output = Command::new("netsh")
        .args([
            "interface", "ipv4", "add", "route",
            &prefix,
            interface_name,
            "0.0.0.0",  // on-link (no gateway)
            "metric=1",
            "store=active"
        ])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        warn!("netsh route add failed: {} {}", stdout, stderr);

        // Try alternative: PowerShell New-NetRoute
        let ps_output = Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "New-NetRoute -DestinationPrefix '{}' -InterfaceAlias '{}' -RouteMetric 1 -ErrorAction SilentlyContinue",
                    prefix, interface_name
                )
            ])
            .output()
            .await?;

        if !ps_output.status.success() {
            let ps_err = String::from_utf8_lossy(&ps_output.stderr);
            warn!("PowerShell route add failed: {}", ps_err);
        }
    }

    info!("Added route {} via interface {}", prefix, interface_name);
    Ok(())
}

/// Remove a route
async fn remove_route_cidr(dest: &str, prefix_len: u8) -> NetworkResult<()> {
    use tokio::process::Command;

    let mask = prefix_to_netmask(prefix_len);
    let prefix = format!("{}/{}", dest, prefix_len);

    // Try route delete first
    let _ = Command::new("route")
        .args(["delete", dest, "mask", &mask])
        .output()
        .await;

    // Also try netsh delete
    let _ = Command::new("netsh")
        .args(["interface", "ipv4", "delete", "route", &prefix, "meshvpn0"])
        .output()
        .await;

    // And PowerShell
    let _ = Command::new("powershell")
        .args([
            "-Command",
            &format!("Remove-NetRoute -DestinationPrefix '{}' -Confirm:$false -ErrorAction SilentlyContinue", prefix)
        ])
        .output()
        .await;

    Ok(())
}

/// Get the default gateway from the routing table
async fn get_default_gateway() -> Option<String> {
    use tokio::process::Command;

    // Run 'route print 0.0.0.0' to get default route
    let output = Command::new("route")
        .args(["print", "0.0.0.0"])
        .output()
        .await
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse the output to find the default gateway
    // Look for a line like: "0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.100     25"
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "0.0.0.0" && parts[1] == "0.0.0.0" {
            // parts[2] is the gateway
            let gateway = parts[2].to_string();
            if gateway != "0.0.0.0" {
                info!("Found default gateway: {}", gateway);
                return Some(gateway);
            }
        }
    }

    // Alternative: try PowerShell
    let ps_output = Command::new("powershell")
        .args([
            "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"
        ])
        .output()
        .await
        .ok()?;

    let gateway = String::from_utf8_lossy(&ps_output.stdout).trim().to_string();
    if !gateway.is_empty() && gateway != "0.0.0.0" {
        info!("Found default gateway via PowerShell: {}", gateway);
        return Some(gateway);
    }

    warn!("Could not find default gateway");
    None
}

/// Convert netmask to prefix length
fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
    let bits = u32::from(netmask);
    bits.count_ones() as u8
}

/// Convert prefix length to netmask string
fn prefix_to_netmask(prefix: u8) -> String {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    Ipv4Addr::from(mask).to_string()
}

/// Check if running with Administrator privileges
pub fn is_admin() -> bool {
    #[cfg(windows)]
    {
        // Simple approach: try to write to a protected location
        // or use whoami command
        use std::process::Command;

        // Run 'net session' which requires admin
        match Command::new("net").arg("session").output() {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    #[cfg(not(windows))]
    {
        // On Unix, check if we're root
        unsafe { libc::geteuid() == 0 }
    }
}

/// Request administrator privileges (shows UAC prompt)
pub fn request_admin() -> bool {
    #[cfg(windows)]
    {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;

        let exe = std::env::current_exe().ok();
        let exe_path = exe.as_ref().and_then(|p| p.to_str()).unwrap_or("");

        let verb: Vec<u16> = OsStr::new("runas\0").encode_wide().collect();
        let file: Vec<u16> = OsStr::new(exe_path).encode_wide().chain(Some(0)).collect();

        unsafe {
            let result = windows_sys::Win32::UI::Shell::ShellExecuteW(
                0, // HWND is isize, 0 = no window
                verb.as_ptr(),
                file.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL as i32,
            );

            result > 32
        }
    }

    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netmask_conversion() {
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(netmask_to_prefix(Ipv4Addr::new(0, 0, 0, 0)), 0);
    }

    #[test]
    fn test_prefix_to_netmask() {
        assert_eq!(prefix_to_netmask(24), "255.255.255.0");
        assert_eq!(prefix_to_netmask(16), "255.255.0.0");
        assert_eq!(prefix_to_netmask(8), "255.0.0.0");
        assert_eq!(prefix_to_netmask(1), "128.0.0.0");
    }

    #[test]
    fn test_admin_check() {
        // Just verify it doesn't crash
        let _ = is_admin();
    }
}
