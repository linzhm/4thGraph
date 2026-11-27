use fourthgraph_stark_counter::run_cli;
use winterfell::{crypto::hashers::Blake3_256, math::fields::f128::BaseElement};

fn main() {
    run_cli::<Blake3_256<BaseElement>>("fourthgraph-stark-counter");
}
