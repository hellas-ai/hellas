use futures::{Stream, StreamExt};
use hellas_rpc::{
    ContentRef, call::ResponseStream, pb::content as pb, services::content::ContentHandler,
};
use hellas_wire::{TransportContext, WireCode, WireStatus};
use std::{
    collections::BTreeMap,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

pub fn reference(object: ContentRef) -> pb::ContentRef {
    pb::ContentRef {
        id: object.id().as_bytes().to_vec(),
        bytes: object.bytes(),
    }
}
#[derive(Clone)]
pub struct File {
    pub bytes: Vec<u8>,
    pub object: ContentRef,
    pub chunks: Vec<hellas_xet::Chunk>,
    pub tree: bool,
}
impl File {
    pub fn new(bytes: Vec<u8>, tree: bool) -> Self {
        Self {
            object: ContentRef::for_bytes(&bytes),
            chunks: hellas_xet::chunk(&bytes),
            bytes,
            tree,
        }
    }
}
#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Good,
    BadDeclarationOnce,
    BadTrailerOnce,
    HoldFirstDeclaration,
}
pub struct Fixture {
    pub files: BTreeMap<String, File>,
    pub mode: Mode,
    pub uploads: AtomicUsize,
    pub reads: AtomicUsize,
    pub corrupt_manifest: AtomicBool,
    pub moved: AtomicBool,
    pub corrupt_bytes: AtomicBool,
    pub entered: tokio::sync::Notify,
}
impl Fixture {
    pub fn new(files: BTreeMap<String, File>, mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            files,
            mode,
            uploads: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            corrupt_manifest: AtomicBool::new(false),
            moved: AtomicBool::new(false),
            corrupt_bytes: AtomicBool::new(false),
            entered: tokio::sync::Notify::new(),
        })
    }
    fn file(&self, at: Option<pb::Path>) -> Result<File, WireStatus> {
        let at = at.ok_or_else(|| WireStatus::new(WireCode::InvalidArgument, "missing path"))?;
        self.files
            .get(&at.path)
            .cloned()
            .ok_or_else(|| WireStatus::new(WireCode::NotFound, "missing fixture file"))
    }
}
#[derive(Clone)]
pub struct Handler(pub Arc<Fixture>);
macro_rules! unused {
    ($method:ident,$request:ty,$response:ty) => {
        async fn $method(
            &self,
            _: $request,
            _: TransportContext,
        ) -> Result<impl Into<hellas_rpc::call::WithTrailer<$response>> + Send, WireStatus> {
            Err::<$response, _>(WireStatus::new(
                WireCode::Unavailable,
                "unused fixture method",
            ))
        }
    };
    ($method:ident,$request:ty,stream $response:ty) => {
        async fn $method(
            &self,
            _: $request,
            _: TransportContext,
        ) -> Result<ResponseStream<$response>, WireStatus> {
            Err(WireStatus::new(
                WireCode::Unavailable,
                "unused fixture method",
            ))
        }
    };
}
impl ContentHandler for Handler {
    async fn stat(
        &self,
        request: pb::StatRequest,
        _: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<pb::StatResponse>> + Send, WireStatus> {
        let file = self.0.file(request.at)?;
        Ok(pb::StatResponse {
            target: Some(pb::Target {
                object: Some(reference(file.object)),
                tree: file.tree,
            }),
        })
    }
    async fn chunks(
        &self,
        request: pb::ChunksRequest,
        _: TransportContext,
    ) -> Result<impl Into<hellas_rpc::call::WithTrailer<pb::ChunksResponse>> + Send, WireStatus>
    {
        let file = self.0.file(request.at)?;
        let mut chunks: Vec<_> = file
            .chunks
            .into_iter()
            .map(|c| pb::Chunk {
                hash: c.hash.as_bytes().to_vec(),
                bytes: c.data_len,
            })
            .collect();
        if self.0.corrupt_manifest.load(Ordering::SeqCst)
            && let Some(first) = chunks.first_mut()
        {
            first.hash[0] ^= 1;
        }
        Ok(pb::ChunksResponse {
            object: Some(reference(file.object)),
            chunks,
            next: None,
        })
    }
    async fn read(
        &self,
        request: pb::ReadRequest,
        _: TransportContext,
    ) -> Result<ResponseStream<pb::ReadResponse>, WireStatus> {
        self.0.reads.fetch_add(1, Ordering::SeqCst);
        let file = self.0.file(request.at)?;
        let object = if self.0.moved.load(Ordering::SeqCst) {
            ContentRef::for_bytes(b"changed pin")
        } else {
            file.object
        };
        if request.start == request.end {
            return Ok(ResponseStream::new(futures::stream::iter([Ok(
                pb::ReadResponse {
                    object: Some(reference(object)),
                    offset: request.start,
                    data: vec![],
                },
            )])));
        }
        let mut responses = Vec::new();
        let mut offset = 0;
        for chunk in file.chunks {
            let end = offset + chunk.data_len;
            if offset < request.end && end > request.start {
                let mut data = file.bytes[offset as usize..end as usize].to_vec();
                if self.0.corrupt_bytes.load(Ordering::SeqCst) {
                    data[0] ^= 1;
                }
                responses.push(Ok(pb::ReadResponse {
                    object: Some(reference(object)),
                    offset,
                    data,
                }));
            }
            offset = end;
        }
        Ok(ResponseStream::new(futures::stream::iter(responses)))
    }
    async fn upload(
        &self,
        mut requests: Pin<Box<dyn Stream<Item = Result<pb::UploadRequest, WireStatus>> + Send>>,
        _: TransportContext,
    ) -> Result<ResponseStream<pb::UploadResponse>, WireStatus> {
        let number = self.0.uploads.fetch_add(1, Ordering::SeqCst);
        let fixture = self.0.clone();
        Ok(ResponseStream::new(async_stream::try_stream! {
            let mut bytes=0u64;let mut written=0u64;let mut next=0u64;
            while let Some(request)=requests.next().await{
                match request?.part.unwrap(){
                    pb::upload_request::Part::Open(open)=>{bytes=open.object.unwrap().bytes;written=0;next=0;yield pb::UploadResponse{next_chunk:0,missing:true,complete:false};},
                    pb::upload_request::Part::List(_)=>{
                        if number==0&&fixture.mode==Mode::HoldFirstDeclaration{fixture.entered.notify_one();futures::future::pending::<()>().await;}
                        yield pb::UploadResponse{next_chunk:next,missing:true,complete:bytes==0||(number==0&&fixture.mode==Mode::BadDeclarationOnce)};
                    },
                    pb::upload_request::Part::Chunk(chunk)=>{written+=chunk.len()as u64;next+=1;yield pb::UploadResponse{next_chunk:next,missing:true,complete:written==bytes};}
                }
            }
            if number==0&&fixture.mode==Mode::BadTrailerOnce{Err(WireStatus::new(WireCode::PermissionDenied,"fixture revoked before trailer"))?;}
        }))
    }
    unused!(acquire,pb::AcquireRequest,stream pb::AcquireResponse);
    unused!(set_pin, pb::SetPinRequest, pb::SetPinResponse);
    unused!(list_pins, pb::ListPinsRequest, pb::ListPinsResponse);
    unused!(watch_pins,pb::WatchPinsRequest,stream pb::WatchPinsResponse);
    unused!(collect, pb::CollectRequest, pb::CollectResponse);
}
