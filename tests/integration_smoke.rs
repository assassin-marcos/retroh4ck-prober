//! End-to-end smoke test: spin up a tiny hyper mock server, run the release
//! prober binary against it, assert the JSONL output contains the expected
//! records.

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;

async fn handle(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path();
    let resp = match path {
        "/admin" => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .header("Server", "nginx/1.20")
            .body(Body::from(
                "<html><head><title>Admin Console</title></head><body>private</body></html>",
            ))
            .unwrap(),
        "/.env" => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain")
            .header("Server", "nginx/1.20")
            .body(Body::from("DB_PASSWORD=secret\nAWS_KEY=AKIA1234567890ABCDEF\n"))
            .unwrap(),
        "/old.zip" => Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header("Location", "/old/backup.zip")
            .header("Server", "nginx/1.20")
            .body(Body::from(""))
            .unwrap(),
        "/private" => Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", r#"Basic realm="x""#)
            .header("Server", "nginx/1.20")
            .body(Body::from("auth required"))
            .unwrap(),
        "/notfound" | _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "text/plain")
            .header("Server", "nginx/1.20")
            .body(Body::from("nope"))
            .unwrap(),
    };
    Ok(resp)
}

async fn start_server() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let addr: SocketAddr = ([127, 0, 0, 1], 0).into();
    let make_svc = make_service_fn(|_| async { Ok::<_, Infallible>(service_fn(handle)) });
    let server = Server::bind(&addr).serve(make_svc);
    let local_addr = server.local_addr();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let graceful = server.with_graceful_shutdown(async {
        let _ = rx.await;
    });
    tokio::spawn(async move {
        if let Err(e) = graceful.await {
            eprintln!("test server error: {e}");
        }
    });
    (local_addr, tx)
}

fn binary_path() -> PathBuf {
    // CARGO_BIN_EXE_<name> is set by cargo when running integration tests
    // against a binary crate.
    PathBuf::from(env!("CARGO_BIN_EXE_retroh4ck-prober"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_jsonl_shape() {
    let (addr, shutdown) = start_server().await;

    // Write hosts + wordlist to temp dir.
    let tmp = tempfile::tempdir().expect("tempdir");
    let hosts_path = tmp.path().join("hosts.txt");
    let words_path = tmp.path().join("words.txt");
    let out_path = tmp.path().join("out.jsonl");

    let base = format!("http://{}", addr);
    std::fs::write(&hosts_path, format!("{}\n", base)).unwrap();
    std::fs::write(&words_path, "admin\n.env\nold.zip\nprivate\nnotfound\n").unwrap();

    let bin = binary_path();
    let status = tokio::process::Command::new(&bin)
        .arg("--list")
        .arg(&hosts_path)
        .arg("--paths")
        .arg(&words_path)
        .arg("--output")
        .arg(&out_path)
        .arg("--threads")
        .arg("4")
        .arg("--timeout")
        .arg("5")
        // disable impersonation — wreq+boringssl handshake against our
        // h1 plaintext mock is unnecessary and just wastes cycles.
        .arg("--impersonate")
        .arg("off")
        .arg("--cf-detect")
        .arg("off")
        // Wildcard probe would hit the 404 branch; turn it off to keep the
        // assertion list deterministic.
        .arg("--no-wildcard")
        .status()
        .await
        .expect("spawn prober");

    let _ = shutdown.send(());
    assert!(status.success(), "prober exited non-zero: {:?}", status);

    let body = std::fs::read_to_string(&out_path).expect("read output");
    let lines: Vec<&str> = body.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "no JSONL records produced");

    // Parse and index by path.
    let mut by_path: std::collections::HashMap<String, serde_json::Value> =
        std::collections::HashMap::new();
    for line in &lines {
        let v: serde_json::Value =
            serde_json::from_str(line).expect("parse jsonl line");
        let path = v.get("path").and_then(|s| s.as_str()).unwrap_or("").to_string();
        by_path.insert(path, v);
    }

    // admin → 200 + title.
    let admin = by_path.get("/admin").expect("/admin record");
    assert_eq!(admin["status_code"].as_u64().unwrap(), 200);
    assert_eq!(admin["title"].as_str().unwrap(), "Admin Console");
    assert_eq!(admin["method"].as_str().unwrap(), "GET");
    assert_eq!(admin["webserver"].as_str().unwrap(), "nginx/1.20");
    assert_eq!(admin["server"].as_str().unwrap(), "nginx/1.20");
    assert!(admin["body_preview"]
        .as_str()
        .unwrap()
        .contains("&lt;html&gt;"));
    assert!(admin["prober"].as_str().unwrap().starts_with("retroh4ck-prober/"));

    // .env → 200 + body preview contains the entity-encoded `=` chars only?
    // Actually .env has no `<` `>` `&` `"` — body_preview should be unchanged.
    let env = by_path.get("/.env").expect("/.env record");
    assert_eq!(env["status_code"].as_u64().unwrap(), 200);
    assert!(env["body_preview"]
        .as_str()
        .unwrap()
        .contains("DB_PASSWORD=secret"));

    // old.zip → 301 with location header.
    let zip = by_path.get("/old.zip").expect("/old.zip record");
    assert_eq!(zip["status_code"].as_u64().unwrap(), 301);
    assert_eq!(zip["location"].as_str().unwrap(), "/old/backup.zip");

    // private → 401.
    let priv_rec = by_path.get("/private").expect("/private record");
    assert_eq!(priv_rec["status_code"].as_u64().unwrap(), 401);

    // notfound → 404, NOT in default match-codes — record must be absent.
    assert!(by_path.get("/notfound").is_none(), "/notfound should be filtered");

    // status_code is an INT, not a string.
    let raw_first = lines[0];
    assert!(
        raw_first.contains("\"status_code\":"),
        "JSONL must contain numeric status_code field"
    );
    assert!(
        !raw_first.contains("\"status_code\":\""),
        "status_code must be numeric, not a string"
    );
}
