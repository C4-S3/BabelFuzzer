use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use proto_fuzzer::protocols::grpc::client_pool::GrpcPool;
use std::sync::Arc;
use tokio::runtime::Runtime;

// Test server implementation
mod server {
    use tonic::{Request, Response, Status};

    pub mod echo {
        tonic::include_proto!("echo");
    }

    use echo::echo_server::Echo;
    use echo::{EchoRequest, EchoResponse};

    #[derive(Debug, Default)]
    pub struct EchoService;

    #[tonic::async_trait]
    impl Echo for EchoService {
        async fn echo_message(
            &self,
            request: Request<EchoRequest>,
        ) -> Result<Response<EchoResponse>, Status> {
            let payload = request.into_inner().payload;
            let response = EchoResponse { payload };
            Ok(Response::new(response))
        }
    }
}

fn throughput_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Spawn test server in the background
    let _server_handle = rt.spawn(async {
        use server::echo::echo_server::EchoServer;
        use tonic::transport::Server;

        let addr = "[::1]:50061".parse().unwrap();
        let echo_service = server::EchoService::default();

        Server::builder()
            .add_service(EchoServer::new(echo_service))
            .serve(addr)
            .await
            .unwrap();
    });

    // Give server time to start
    std::thread::sleep(std::time::Duration::from_millis(200));

    let mut group = c.benchmark_group("grpc_throughput");

    // Benchmark different pool sizes
    for pool_size in [1, 2, 4, 8].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("pool_size_{}", pool_size)),
            pool_size,
            |b, &pool_size| {
                b.iter(|| {
                    rt.block_on(async {
                        // Create pool
                        let pool = Arc::new(
                            GrpcPool::new("http://[::1]:50061", pool_size)
                                .await
                                .expect("Failed to create pool")
                        );

                        // Run 1000 echo requests in parallel
                        let mut handles = vec![];
                        for i in 0..1000 {
                            let pool_clone = pool.clone();
                            let handle = tokio::spawn(async move {
                                let data = format!("request_{}", i).into_bytes();
                                pool_clone.echo(data).await
                            });
                            handles.push(handle);
                        }

                        // Wait for all requests to complete
                        for handle in handles {
                            let _ = handle.await.unwrap();
                        }
                    })
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, throughput_benchmark);
criterion_main!(benches);
