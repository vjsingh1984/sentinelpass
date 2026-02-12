use anyhow::Result;
use sentinelpass_core::daemon::NativeMessagingHost;
use tracing::{error, info};
use tracing_subscriber::FmtSubscriber;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> Result<()> {
    // Initialize logging to stderr (native messaging uses stdout)
    let subscriber = FmtSubscriber::builder()
        .with_writer(std::io::stderr)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("Starting SentinelPass Native Messaging Host v{}", VERSION);

    // Run the native messaging host
    let mut host = NativeMessagingHost::new();

    match host.run() {
        Ok(()) => {
            info!("Native messaging host completed successfully");
            Ok(())
        }
        Err(e) => {
            error!("Native messaging host error: {}", e);
            anyhow::bail!("Native messaging host failed: {}", e)
        }
    }
}
