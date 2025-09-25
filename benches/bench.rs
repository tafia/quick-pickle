use std::io::Read;

use criterion::Criterion;

fn bench_picklefile(c: &mut Criterion, filename: &str) {
    // Load the picklefile
    let mut contents = vec![];
    let mut f = std::fs::File::open(filename).unwrap();
    f.read_to_end(&mut contents).unwrap();

    // Run the benchmark
    c.bench_function(filename, |b| {
        b.iter(|| {
            let mut reader = quick_pickle::reader::Reader::new(&*contents);
            let _ = reader.par_collect_events().unwrap();
        })
    });
}

pub fn criterion_benchmark(c: &mut Criterion) {
    bench_picklefile(c, "benches/data/biglist.pickle");
    bench_picklefile(c, "benches/data/manyrefs.pickle");
    bench_picklefile(c, "benches/data/manystrings.pickle");
}

criterion::criterion_group!(benches, criterion_benchmark);
criterion::criterion_main!(benches);
