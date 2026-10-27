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
fn module() -> &'static RuntimeModule {
    static MODULE: OnceLock<RuntimeModule> = OnceLock::new();
    MODULE.get_or_init(|| {
        compile::compile_sources(&[SOURCE.to_owned()], catena_lang::codegen::GpuDialect::Hip)
            .unwrap()
    })
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
    fn load(
        &mut self,
        module: &RuntimeModule,
        _retention: hellas_rpc::Retention,
    ) -> Result<super::Cancellation> {
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
