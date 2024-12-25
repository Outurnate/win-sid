test:
  cargo llvm-cov --workspace --lcov --output-path lcov.info

doc:
  cargo doc