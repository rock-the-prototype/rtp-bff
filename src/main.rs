use rtp_bff::app;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:3000").await?;

    axum::serve(listener, app()).await
}
