use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    Request as HttpRequest, Response,
};
use hyper_util::rt::TokioIo;
use kan::{
    evidence_crypto as crypto,
    evidence_reader::{Reader, ScopeAccess},
    evidence_service::{
        self as svc, Command, Failure, Grant, Output, Request, Service, SignedRequest,
    },
    evidence_store::Ledger,
    sign::Identity,
};
use std::{
    convert::Infallible,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex,
    },
};
use tokio::task::{JoinHandle, JoinSet};

fn mutate_record(row: &mut svc::RecordView, mode: u8) {
    use atproto_dasl::Ipld;
    use kan::evidence::{self, Decoded};
    let decode = |bytes: &str| {
        let Decoded::Known(record) =
            evidence::decode(&svc::unhex(bytes, evidence::MAX_RECORD_BYTES).unwrap()).unwrap()
        else {
            panic!("known record")
        };
        record
    };
    let encode = |kind: &str, body: std::collections::BTreeMap<String, Ipld>| {
        let value = Ipld::Map(
            [
                ("v".into(), Ipld::Integer(1)),
                ("kind".into(), Ipld::String(kind.into())),
                ("body".into(), Ipld::Map(body)),
            ]
            .into_iter()
            .collect(),
        );
        let Decoded::Known(record) = evidence::encode(&value).unwrap() else {
            panic!("known record")
        };
        record
    };
    let manifest = decode(&row.manifest);
    let receipt = decode(&row.receipt);
    let mut mb = manifest.body().clone();
    let mut rb = receipt.body().clone();
    if mode == 4 {
        mb.insert("scopeToken".into(), Ipld::Bytes(vec![99; 32]));
        let manifest = encode("manifest", mb);
        rb.insert("scopeToken".into(), Ipld::Bytes(vec![99; 32]));
        rb.insert("manifest".into(), Ipld::Link(manifest.cid().clone()));
        row.manifest = svc::hex(manifest.bytes());
    } else if mode == 9 {
        mb.insert("writer".into(), rb["issuer"].clone());
        let manifest = encode("manifest", mb);
        rb.insert("manifest".into(), Ipld::Link(manifest.cid().clone()));
        row.manifest = svc::hex(manifest.bytes());
    } else {
        rb.insert("issuer".into(), mb["writer"].clone());
    }
    row.receipt = svc::hex(encode("receipt", rb).bytes());
}

struct Fixture {
    dir: tempfile::TempDir,
    scope: [u8; 32],
    private: [u8; 32],
    issuer: String,
    endpoint: String,
    service: Arc<Mutex<Service>>,
    #[allow(dead_code, reason = "Fault modes are exercised by the integration suite sharing this fixture")]
    mode: Arc<AtomicU8>,
    server: JoinHandle<()>,
    writer: Identity,
    previous: Option<String>,
    position: u64,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new(scope: u8, reader: &Identity) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = Identity::generate();
        key.save(&dir.path().join("server.key")).unwrap();
        let writer = Identity::generate();
        writer.save(&dir.path().join("writer.key")).unwrap();
        let issuer = key.did().to_string();
        let scope = [scope; 32];
        let service = Arc::new(Mutex::new(
            Service::new(
                Ledger::create(&dir.path().join("archive")).unwrap(),
                scope,
                key,
                vec![
                    Grant {
                        principal: reader.did().to_string(),
                        append: false,
                        inventory: true,
                    },
                    Grant {
                        principal: writer.did().to_string(),
                        append: true,
                        inventory: false,
                    },
                ],
            )
            .unwrap(),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/v1/rpc", listener.local_addr().unwrap());
        let mode = Arc::new(AtomicU8::new(0));
        let state = service.clone();
        let fault = mode.clone();
        let signing = dir.path().join("server.key");
        let server = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=>{let (stream,_)=accepted.unwrap();let state=state.clone();let fault=fault.clone();let signing=signing.clone();tasks.spawn(async move {
                        let handler=hyper::service::service_fn(move |r:HttpRequest<Incoming>| {let state=state.clone();let fault=fault.clone();let signing=signing.clone();async move {
                            let bytes=r.into_body().collect().await.unwrap().to_bytes();
                            let mut reply=state.lock().unwrap().dispatch(&bytes,kan::evidence_operations::now()).unwrap();
                            let mode=fault.load(Ordering::Relaxed);
                            if mode==10 {std::future::pending::<()>().await;}
                            if mode==11 && matches!(reply.reply.result,Ok(Output::Evidence{..})) {
                                let request=SignedRequest::decode(&bytes).unwrap();
                                let scope: [u8;32]=svc::unhex(&request.request.scope,32).unwrap().try_into().unwrap();
                                let replacement=Service::new(Ledger::open(&signing.with_file_name("archive")).unwrap(),scope,Identity::load_existing(&signing).unwrap(),vec![]).unwrap();
                                *state.lock().unwrap()=replacement;
                            }
                            if mode==1 {reply.signature="00".repeat(64);}
                            if mode==2 {if let Ok(Output::Page{records,..})=&mut reply.reply.result {if let Some(row)=records.first_mut(){row.sequence+=1;}}}
                            if mode==3 {if let Ok(Output::Evidence{record,..})=&mut reply.reply.result {record.sequence+=1;}}
                            if mode==4 || mode==5 || mode==9 { if let Ok(Output::Page{records,..})=&mut reply.reply.result { if let Some(row)=records.first_mut() { mutate_record(row,mode); } } }
                            if mode==6 {if let Ok(Output::Evidence{signed_request,..})=&mut reply.reply.result {
                                let mut retained=SignedRequest::decode(&svc::unhex(signed_request,svc::MAX_REQUEST).unwrap()).unwrap();
                                if let Command::Append{id,..}=&mut retained.request.command {*id="ff".repeat(16);}
                                *signed_request=svc::hex(&SignedRequest::sign(retained.request,&Identity::load_existing(&signing.with_file_name("writer.key")).unwrap()).unwrap().bytes().unwrap());
                            }}
                            if mode==7 {if let Ok(Output::Page{complete,..})=&mut reply.reply.result {*complete = !*complete;}}
                            if mode==8 {if let Ok(Output::Page{records,complete})=&mut reply.reply.result {records.clear();*complete=false;}}
                            if (2..=9).contains(&mode) {
                                use sha2::{Digest,Sha256};
                                let mut preimage=b"tools.kan.service.reply.v1\0".to_vec();preimage.extend_from_slice(&Sha256::digest(serde_json::to_vec(&reply.reply).unwrap()));
                                reply.signature=svc::hex(&Identity::load_existing(&signing).unwrap().sign(&preimage).unwrap());
                            }
                            Ok::<_,Infallible>(Response::new(Full::new(Bytes::from(reply.bytes().unwrap()))))
                        }});
                        let _=hyper::server::conn::http1::Builder::new().keep_alive(false).serve_connection(TokioIo::new(stream),handler).await;
                    });},
                    _=tasks.join_next(),if !tasks.is_empty()=>{}
                }
            }
        });
        Self {
            dir,
            scope,
            private: [27; 32],
            issuer,
            endpoint,
            service,
            mode,
            server,
            writer,
            previous: None,
            position: 0,
        }
    }
    fn access(&self) -> ScopeAccess {
        ScopeAccess {
            scope: self.scope,
            private_key: self.private,
            issuer: self.issuer.clone(),
            endpoint: self.endpoint.clone(),
        }
    }
    fn append(&mut self, plain: &[u8]) {
        let request = SignedRequest::sign(
            Request {
                version: 1,
                scope: svc::hex(&self.scope),
                principal: self.writer.did().to_string(),
                audience: self.issuer.clone(),
                expires: None,
                command: Command::Append {
                    id: format!("{:032x}", self.position + 1),
                    position: self.position,
                    previous: self.previous.clone(),
                    ciphertext: svc::hex(
                        &crypto::seal(
                            &crypto::public_key(&self.private).unwrap(),
                            &self.scope,
                            plain,
                        )
                        .unwrap(),
                    ),
                },
            },
            &self.writer,
        )
        .unwrap()
        .bytes()
        .unwrap();
        let reply = self
            .service
            .lock()
            .unwrap()
            .dispatch(&request, kan::evidence_operations::now())
            .unwrap();
        let Ok(Output::Committed { record, .. }) = reply.reply.result else {
            panic!("append failed")
        };
        let kan::evidence::Decoded::Known(manifest) = kan::evidence::decode(
            &svc::unhex(&record.manifest, kan::evidence::MAX_RECORD_BYTES).unwrap(),
        )
        .unwrap() else {
            panic!("manifest required")
        };
        self.previous = Some(manifest.cid().to_string());
        self.position += 1;
    }
    fn revoke(&self) {
        let replacement = Service::new(
            Ledger::open(&self.dir.path().join("archive")).unwrap(),
            self.scope,
            Identity::load_existing(&self.dir.path().join("server.key")).unwrap(),
            vec![],
        )
        .unwrap();
        *self.service.lock().unwrap() = replacement;
    }
}
