use anyhow::Result;
use core::RequestCode;
use clap::Parser;
use fastwebsockets::{
    handshake::{self, generate_key},
    FragmentCollector, Frame, OpCode, Payload, WebSocket,
};
use hyper::{
    body::Bytes,
    header::{CONNECTION, UPGRADE},
    rt::Executor,
    upgrade::Upgraded,
    Request,
};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;

use std::{future::Future, sync::Arc};

use http_body_util::Empty;
use hyper_util::rt::TokioIo;

use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// User name
    #[arg(long)]
    login: String,
    /// Password of the user
    #[arg(long)]
    password: String,
    /// QUIK server host name
    #[arg(long)]
    host: String,
    /// QUIK server port
    #[arg(long)]
    port: u16,
    /// URI path to connect via websocket
    #[arg(long)]
    uri: String,
}

fn tls_config() -> Result<Arc<ClientConfig>> {
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

fn open_msg(login: &str, password: &str) -> String {
    format!(
        r#"{{"msgid":{:?},"login":"{}","password":"{}"}}"#,
        RequestCode::Auth, login, password
    )
}

async fn connect(host: String, port: u16, uri: String) -> Result<WebSocket<TokioIo<Upgraded>>> {
    let sock = TcpStream::connect(&format!("{host}:{port}")).await?;
    let request = Request::builder()
        .method("GET")
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "Upgrade")
        .header("Origin", &format!("https://{host}"))
        .header("Host", &host)
        .header("Sec-WebSocket-Key", generate_key())
        .header("Sec-WebSocket-Version", "13")
        .uri(&format!("/{uri}"))
        .body(Empty::<Bytes>::new())?;
    let config = tls_config().unwrap();
    let dns: ServerName = host.try_into().expect("Can't create server name");
    let connector = TlsConnector::from(config);
    let stream = connector.connect(dns, sock).await?;
    let (ws, _) = handshake::client(&SpawnExecutor, request, stream).await?;
    Ok(ws)
}

struct SpawnExecutor;

impl<Fut> Executor<Fut> for SpawnExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        tokio::spawn(fut);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let ws = connect(args.host, args.port, args.uri).await?;
    let mut fc = FragmentCollector::new(ws);

    let open_msg = open_msg(&args.login, &args.password);
    let payload = Payload::Borrowed(open_msg.as_bytes());
    fc.write_frame(Frame::text(payload)).await?;

    loop {
        let msg = match fc.read_frame().await {
            Ok(msg) => msg,
            Err(e) => {
                println!("Error reading frame: {:?}", e);
                fc.write_frame(Frame::close_raw(vec![].into())).await?;
                break;
            }
        };

        match msg.opcode {
            OpCode::Close => break,
            OpCode::Binary | OpCode::Text => {
                let payload: String = String::from_utf8_lossy(&msg.payload).to_string();
                println!("Received message: {payload}",);
            }
            _ => {}
        }
    }
    Ok(())
}
