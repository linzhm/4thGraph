use fourthgraph_stark_counter::run_cli;

mod hash;

fn main() {
    run_cli::<hash::Sha256>("fourthgraph-stark-sha256");
}
