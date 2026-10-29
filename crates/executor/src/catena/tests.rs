use super::{
    assets::Assets,
    compile,
    driver::{self, Device},
    validate,
};
use catena_lang::{
    codegen::GpuDialect,
    runtime::{GeneratedFunction, RuntimeModule, Value, ValueKind as K},
};
use hellas_channel::content::InvocationContent;
use hellas_rpc::protocol::invocation::{Limits, compute::*};
use hellas_store::ContentStore;
use std::{collections::BTreeMap, process::Command, sync::OnceLock};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const SOURCE: &str = r#"(def program initialize : [] -> (u64 val) = const.u64.0x0000000000000000)
(def program advance : {(u64 val) (u64 val)} -> (u64 val)
= ({smolcat.value.named smolcat.value.named stdlib.numeric.numeric.u64} stdlib.numeric.+ :.forget))
"#;
fn complete_sources(source: &str) -> Vec<String> {
    catena_lang::stdlib::core_sources()
        .map(|s| -> &str { s })
        .chain(std::iter::once(source))
        .map(str::to_owned)
        .collect()
}
fn module() -> &'static RuntimeModule {
    static MODULE: OnceLock<RuntimeModule> = OnceLock::new();
    MODULE.get_or_init(|| {
        compile::compile_sources(&complete_sources(SOURCE), GpuDialect::Hip).unwrap()
    })
}

#[test]
fn provider_requires_the_program_to_ship_its_stdlib() {
    let dialect = GpuDialect::Hip;
    let complete = complete_sources(SOURCE);
    let missing = vec![SOURCE.to_owned()];
    assert!(compile::compile_sources(&missing, dialect).is_err());
    assert!(compile::compile_sources(&complete, dialect).is_ok());
    let exe = std::env::current_exe().unwrap();
    for retention in [
        hellas_rpc::Retention::Ephemeral,
        hellas_rpc::Retention::Retain,
    ] {
        let compile = |sources: &[String]| {
            compile::compile_cancellable(
                sources,
                &exe,
                &super::Cancellation::default(),
                retention,
                dialect,
            )
        };
        assert!(compile(&missing).is_err(), "missing stdlib: {retention:?}");
        assert!(
            compile(&complete).is_ok(),
            "complete program: {retention:?}"
        );
    }
}
fn limits() -> Limits {
    Limits {
        max_upload_bytes: 1024,
        max_output_bytes: 1024,
        max_steps: 64,

        execution_timeout_ms: 1000,
    }
}
fn environment() -> Environment {
    Environment {
        sources: vec![],
        assets: vec![],
    }
}
fn counter() -> Plan {
    Plan {
        calls: vec![Call {
            entry: "initialize".into(),
            args: vec![],
            bind: vec![Bind::Name("value".into())],
        }],
        step: Some(Step {
            entry: "advance".into(),
            args: vec![
                StepArg::Arg(Arg::Slot {
                    name: "value".into(),
                }),
                StepArg::Arg(Arg::U64(1)),
            ],
            bind: vec![Bind::Name("value".into())],
            emit: "value".into(),
            stop: Stop {
                any_of: vec![5],
                max_steps: 64,
            },
        }),
        outputs: vec![Declared {
            slot: "value".into(),
            kind: OutputKind::Scalar(ValueKind::U64),
        }],
    }
}

/// Executes the actual Hex-generated scalar C ABI with a host C++ compiler.
/// The header rejects any GPU operation; there is no arithmetic model in Rust.
struct HostScalarDevice {
    _dir: tempfile::TempDir,
    library: Option<libloading::Library>,
    signatures: Vec<GeneratedFunction>,
    cancel: super::Cancellation,
    loads: usize,
    calls: usize,
}
impl HostScalarDevice {
    fn new() -> Self {
        Self {
            _dir: tempfile::tempdir().unwrap(),
            library: None,
            signatures: vec![],
            cancel: super::Cancellation::default(),
            loads: 0,
            calls: 0,
        }
    }
}
impl Device for HostScalarDevice {
    fn load(&mut self, module: &RuntimeModule) -> Result<super::Cancellation> {
        self.loads += 1;
        let dir = self._dir.path();
        std::fs::create_dir_all(dir.join("hip"))?;
        std::fs::write(
            dir.join("hip/hip_runtime.h"),
            "#pragma once\n#include <cstdlib>\n#define __host__\n#define __device__\nusing hipError_t = int;\nconstexpr int hipSuccess = 0;\ninline const char* hipGetErrorString(int) { std::abort(); }\ninline int hipMalloc(void**, size_t) { std::abort(); }\nstruct dim3 { unsigned x,y,z; dim3(unsigned a,unsigned b,unsigned c):x(a),y(b),z(c){} };\n",
        )?;
        std::fs::write(dir.join("module.cpp"), &module.source)?;
        let output = Command::new("c++")
            .args(["-std=c++17", "-shared", "-fPIC", "-O1", "-I"])
            .arg(dir)
            .arg(dir.join("module.cpp"))
            .arg("-o")
            .arg(dir.join("module.so"))
            .output()?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
        }
        self.library = Some(unsafe { libloading::Library::new(dir.join("module.so"))? });
        self.signatures = module.functions.clone();
        Ok(self.cancel.clone())
    }
    fn call(&mut self, entry: &str, args: Vec<Value<'_>>) -> Result<Vec<Value<'static>>> {
        self.calls += 1;
        let signature = self
            .signatures
            .iter()
            .find(|f| f.source_name == entry)
            .ok_or("unknown entry")?;
        assert_eq!(signature.outputs, vec![K::U64]);
        assert!(signature.inputs.iter().all(|k| *k == K::U64));
        let args: Vec<_> = args
            .into_iter()
            .map(|v| match v {
                Value::U64(n) => n,
                _ => panic!("not u64"),
            })
            .collect();
        let lib = self.library.as_ref().unwrap();
        let mut result = 0;
        unsafe {
            match args.as_slice() {
                [] => lib.get::<unsafe extern "C" fn(*mut u64)>(signature.symbol.as_bytes())?(
                    &mut result,
                ),
                [a] => lib
                    .get::<unsafe extern "C" fn(u64, *mut u64)>(signature.symbol.as_bytes())?(
                    *a,
                    &mut result,
                ),
                [a, b] => {
                    lib.get::<unsafe extern "C" fn(u64, u64, *mut u64)>(
                        signature.symbol.as_bytes(),
                    )?(*a, *b, &mut result)
                }
                _ => return Err("unsupported scalar fixture arity".into()),
            }
        }
        Ok(vec![Value::U64(result)])
    }
}

#[test]
fn counter_and_first_then_resolve_by_step_index() {
    let mut plan = counter();
    let step = plan.step.as_mut().unwrap();
    step.args[1] = StepArg::FirstThen {
        first: Arg::U64(2),
        then: Arg::Counter { base: 2 },
    };
    step.stop = Stop {
        any_of: vec![],
        max_steps: 3,
    };
    let mut observed = vec![];
    let result = driver::execute(
        &mut HostScalarDevice::new(),
        module(),
        &environment(),
        &BTreeMap::new(),
        &plan,
        &limits(),
        &Assets::new(0, catena_lang::codegen::GpuDialect::Hip),
        &InvocationContent::Retained(ContentStore::new()),
        |v| {
            observed.push(v);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(observed, vec![2, 5, 9]);
    assert_eq!(result.stop, Some(StopReason::MaxSteps));
}

#[test]
fn invalid_plan_never_loads_or_calls_a_device() {
    for mode in 0..9 {
        let mut plan = counter();
        let mut limit = limits();
        match mode {
            0 => plan.calls[0].entry = "absent".into(),
            1 => plan.calls[0].args.push(Arg::U64(0)),
            2 => plan.step.as_mut().unwrap().args[1] = StepArg::Arg(Arg::U32(1)),
            3 => {
                plan.step.as_mut().unwrap().args[0] = StepArg::Arg(Arg::Slot {
                    name: "unbound".into(),
                })
            }
            4 => plan.step.as_mut().unwrap().bind.clear(),
            5 => plan.step.as_mut().unwrap().stop.max_steps = 65,
            6 => limit.max_output_bytes = 519,
            7 => plan.outputs[0].kind = OutputKind::Scalar(ValueKind::U32),
            _ => {
                plan.step.as_mut().unwrap().args[1] = StepArg::Arg(Arg::Counter { base: u64::MAX })
            }
        }
        let mut device = HostScalarDevice::new();
        assert!(
            driver::execute(
                &mut device,
                module(),
                &environment(),
                &BTreeMap::new(),
                &plan,
                &limit,
                &Assets::new(0, catena_lang::codegen::GpuDialect::Hip),
                &InvocationContent::Retained(ContentStore::new()),
                |_| Ok(())
            )
            .is_err(),
            "mode {mode}"
        );
        assert_eq!((device.loads, device.calls), (0, 0), "mode {mode}");
    }
}

#[test]
fn slot_moves_asset_ownership_and_recurrent_flow_are_checked() {
    let module = RuntimeModule::new(
        GpuDialect::Hip,
        "",
        [
            GeneratedFunction {
                source_name: "init".into(),
                symbol: "".into(),
                inputs: vec![],
                outputs: vec![K::MemOwn],
            },
            GeneratedFunction {
                source_name: "take".into(),
                symbol: "".into(),
                inputs: vec![K::MemOwn],
                outputs: vec![K::MemOwn],
            },
            GeneratedFunction {
                source_name: "borrow-take".into(),
                symbol: "".into(),
                inputs: vec![K::MemRef, K::MemOwn],
                outputs: vec![],
            },
        ],
    );
    let mut plan = Plan {
        calls: vec![
            Call {
                entry: "init".into(),
                args: vec![],
                bind: vec![Bind::Name("s".into())],
            },
            Call {
                entry: "take".into(),
                args: vec![Arg::Slot { name: "s".into() }],
                bind: vec![Bind::Discard],
            },
            Call {
                entry: "take".into(),
                args: vec![Arg::Slot { name: "s".into() }],
                bind: vec![Bind::Discard],
            },
        ],
        step: None,
        outputs: vec![],
    };
    assert_eq!(
        validate::validate(
            &module,
            &environment(),
            &BTreeMap::new(),
            &plan,
            &limits(),
            &InvocationContent::Retained(ContentStore::new())
        )
        .unwrap_err()
        .call,
        2
    );
    plan.calls.truncate(1);
    plan.calls.push(Call {
        entry: "borrow-take".into(),
        args: vec![
            Arg::Slot { name: "s".into() },
            Arg::Slot { name: "s".into() },
        ],
        bind: vec![],
    });
    assert!(
        validate::validate(
            &module,
            &environment(),
            &BTreeMap::new(),
            &plan,
            &limits(),
            &InvocationContent::Retained(ContentStore::new())
        )
        .is_err()
    );
    plan.calls[1] = Call {
        entry: "take".into(),
        args: vec![Arg::Asset {
            name: "w".into(),
            offset: 0,
            bytes: 8,
        }],
        bind: vec![Bind::Discard],
    };
    let env = Environment {
        sources: vec![],
        assets: vec![NamedAsset {
            name: "w".into(),
            object: hellas_rpc::ContentRef::for_bytes(&[0; 8]),
        }],
    };
    assert!(
        validate::validate(
            &module,
            &env,
            &BTreeMap::new(),
            &plan,
            &limits(),
            &InvocationContent::Retained(ContentStore::new())
        )
        .is_err()
    );
    let mut plan = counter();
    plan.calls[0].bind = vec![Bind::Name("initial".into())];
    plan.step.as_mut().unwrap().args[0] = StepArg::FirstThen {
        first: Arg::Slot {
            name: "initial".into(),
        },
        then: Arg::Slot {
            name: "initial".into(),
        },
    };
    assert!(
        validate::validate(
            super_module(),
            &environment(),
            &BTreeMap::new(),
            &plan,
            &limits(),
            &InvocationContent::Retained(ContentStore::new())
        )
        .is_err()
    );
}
fn super_module() -> &'static RuntimeModule {
    module()
}

// SafeRuntime and the compile child re-execute this test binary.
#[ctor::ctor(unsafe)]
fn catena_child() {
    if super::child_main().unwrap() {
        std::process::exit(0);
    }
}

const SPIN: &str = r#"(theory type nat {
(arr spin-fold.end : 0 -> 1)
(arr spin-fold.index : 0 -> 1)
})
(theory program type {
(arr meta.spin-fold.end : 1 -> spin-fold.end)
})
(def program spin-add : {(u64 val) (u64 val)} -> (u64 val)
= ({smolcat.value.named smolcat.value.named stdlib.numeric.numeric.u64} stdlib.numeric.+ :.forget))
(def program spin-multiply : {(u64 val) (u64 val)} -> (u64 val)
= ({smolcat.value.named smolcat.value.named stdlib.numeric.numeric.u64} stdlib.numeric.* :.forget))
(def program spin-step : {(u64 val) ({({spin-fold.index u32} :) ({(u64 val) ({(({spin-fold.index spin-fold.end} prop.Less) |-) (prop.Truth |-)} *)} *)} *)} -> ({(u64 val) (prop.Truth |-)} *)
= ([factor pair.]
  ([.pair] *.elim [index rest.])
  ([.rest] *.elim [total proofs.])
  ([.proofs] *.elim [less truth.])
  ([.less] unsafe.discard unit.elim)
  ([.index] stdlib.numeric.to_u64 :.forget [i.])
  ({({[.total] [.factor]} spin-multiply) [.i]} spin-add [next.])
  ({[.next] [.truth]} *.intro)))
(def program spin : {(u64 val) (u32 val)} -> (u64 val)
= ([factor steps.]
  ({[.factor]} partial.spin-step.1 [callback.])
  ({[.steps] (unit.intro meta.spin-fold.end)} smolcat.value.named_at [end.])
  ({[.end] const.u64.0x0000000000000000 [.callback] core.truth} core.fold.bounded [result proof.])
  ([.proof] unsafe.discard unit.elim)
  [.result]))
"#;

/// Manual Strix evidence (plan-v4 §6 GPU variant, 8c): an unseen program
/// compiled by the compile child runs in a SafeRuntime worker (41 → 42); a
/// 2³²-step fold is cancelled, its worker process is gone, and the next job
/// succeeds on a respawned worker. Run on a gfx1151 host from the repo root.
/// It uses the `.#rocm` toolkit from the default shell, without
/// `LD_LIBRARY_PATH`, because that toolkit's `lib` ships its own glibc:
///
/// ```sh
/// R=$(nix eval --raw .#devShells.x86_64-linux.rocm --apply 's: toString (builtins.filter (p: p.name == "hellas-rocm-toolkit") s.nativeBuildInputs)') && nix develop -c env -u LD_LIBRARY_PATH ROCM_PATH=$R bash -c "PATH=\$PATH:$R/bin cargo test -p hellas-executor --lib catena::tests::hip_unseen_program_and_kill_respawn -- --ignored --nocapture"
/// ```
#[test]
#[ignore = "needs a HIP device; run manually on Strix"]
fn hip_unseen_program_and_kill_respawn() {
    use super::{Cancellation, pool::Pool};
    use std::time::{Duration, Instant};

    let dialect = GpuDialect::Hip;
    let exe = std::env::current_exe().unwrap();
    let compile = |source: &str| {
        compile::compile_cancellable(
            &complete_sources(source),
            &exe,
            &Cancellation::default(),
            hellas_rpc::Retention::Ephemeral,
            dialect,
        )
        .unwrap()
    };
    let increment = compile(
        "(def program increment : (u64 val) -> (u64 val) = ({_ const.u64.0x0000000000000001} {smolcat.value.named smolcat.value.named stdlib.numeric.numeric.u64} stdlib.numeric.+ :.forget))\n",
    );
    let spin = compile(SPIN);
    let limits = Limits {
        execution_timeout_ms: 60_000,
        ..limits()
    };
    let single = |entry: &str, args: Vec<Arg>| Plan {
        calls: vec![Call {
            entry: entry.into(),
            args,
            bind: vec![Bind::Name("answer".into())],
        }],
        step: None,
        outputs: vec![Declared {
            slot: "answer".into(),
            kind: OutputKind::Scalar(ValueKind::U64),
        }],
    };
    let pool = Pool::new(1, 4).unwrap();
    let run = |module: &RuntimeModule, plan: &Plan, lease: &mut super::pool::Lease| {
        driver::execute(
            lease,
            module,
            &environment(),
            &BTreeMap::new(),
            plan,
            &limits,
            &Assets::new(0, dialect),
            &InvocationContent::Retained(ContentStore::new()),
            |_| Ok(()),
        )
    };
    let timeout = Duration::from_millis(limits.execution_timeout_ms);
    let add_one = single("increment", vec![Arg::U64(41)]);

    let mut lease = pool.lease(&increment, timeout).unwrap();
    let done = run(&increment, &add_one, &mut lease).unwrap();
    assert_eq!(done.outputs["answer"], 42u64.to_le_bytes());
    let first = lease.pid().unwrap();
    drop(lease);
    println!("increment(41) = 42 on worker pid {first}");

    // Load the spin artifact on the warm worker first, so the cancel below
    // lands inside the running fold rather than in the HIP module load.
    const FACTOR: u64 = 6364136223846793005;
    let mut lease = pool.lease(&spin, timeout).unwrap();
    let done = run(
        &spin,
        &single("spin", vec![Arg::U64(FACTOR), Arg::U32(3)]),
        &mut lease,
    )
    .unwrap();
    assert_eq!(done.outputs["answer"], FACTOR.wrapping_add(2).to_le_bytes());
    assert_eq!(lease.pid(), Some(first));
    drop(lease);

    let mut lease = pool.lease(&spin, timeout).unwrap();
    let cancel = lease.cancellation();
    let killer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(500));
        cancel.cancel();
    });
    let start = Instant::now();
    let spun = run(
        &spin,
        &single("spin", vec![Arg::U64(FACTOR), Arg::U32(u32::MAX)]),
        &mut lease,
    );
    let elapsed = start.elapsed();
    killer.join().unwrap();
    assert_eq!(lease.pid(), Some(first), "spin ran on the warm worker");
    let error = spun.unwrap_err();
    drop(lease);
    assert!(elapsed < Duration::from_secs(5), "cancel took {elapsed:?}");
    assert!(
        !std::path::Path::new(&format!("/proc/{first}")).exists(),
        "cancelled worker {first} survived"
    );
    println!("spin cancelled after {elapsed:?}: {error}; worker {first} gone");

    let mut lease = pool.lease(&increment, timeout).unwrap();
    let done = run(&increment, &add_one, &mut lease).unwrap();
    assert_eq!(done.outputs["answer"], 42u64.to_le_bytes());
    let next = lease.pid().unwrap();
    assert_ne!(next, first);
    println!("increment(41) = 42 on respawned worker pid {next}");
}
