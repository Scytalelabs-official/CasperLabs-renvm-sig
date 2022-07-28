# CasperLabs-renvm-sig

A library to construct mock RenVm signatures for cross-chain lock-and-mint
operations.

# Setup
```
$ cargo build
```

# Usage
* Random RenVm secret key and message
```rust
let renvm = RenVm::random();
let renvm_msg = RenVmMsgBuilder::default().build().unwrap();
let _renvm_sig = renvm.sign(&renvm_msg).unwrap();
```
* RenVm secret key from bytes
```rust
let sk_bytes = [0u8; 32];
let _renvm = RenVm::from_bytes(&sk_bytes).unwrap();
```
* RenVm secret key from hex string
```rust
let sk = "0x0000000000000000000000000000000000000000000000000000000000000000";
let _renvm = RenVm::from_str(sk).unwrap();
```
* Builder pattern for RenVm message
```rust
// RenVm message structure
// | p_hash | amount | s_hash | to | n_hash |
// |   32   |   8    |   32   | 32 |   32   |
// random `to` and `n_hash`
let (p_hash, amount, s_hash) = ([0u8; 32], 0u64, [0u8; 32]);
let _renvm_msg = RenVmMsgBuilder::default()
  .p_hash(p_hash)
  .amount(amount)
  .s_hash(s_hash)
  .build()
  .unwrap();
```