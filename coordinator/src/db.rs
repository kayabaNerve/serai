pub use serai_db::*;

use crate::tributary::TributarySpec;

#[derive(Debug)]
pub struct MainDb<'a, D: Db>(&'a mut D);
impl<'a, D: Db> MainDb<'a, D> {
  pub fn new(db: &'a mut D) -> Self {
    Self(db)
  }

  fn main_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"MAIN", dst, key)
  }

  fn acive_tributaries_key() -> Vec<u8> {
    Self::main_key(b"active_tributaries", [])
  }
  pub fn active_tributaries(&self) -> (Vec<u8>, Vec<TributarySpec>) {
    let bytes = self.0.get(Self::acive_tributaries_key()).unwrap_or(vec![]);
    let mut bytes_ref: &[u8] = bytes.as_ref();

    let mut tributaries = vec![];
    while !bytes_ref.is_empty() {
      tributaries.push(TributarySpec::read(&mut bytes_ref).unwrap());
    }

    (bytes, tributaries)
  }
  pub fn add_active_tributary(&mut self, spec: &TributarySpec) {
    let key = Self::acive_tributaries_key();
    let (mut existing_bytes, existing) = self.active_tributaries();
    for tributary in &existing {
      if tributary == spec {
        return;
      }
    }

    spec.write(&mut existing_bytes).unwrap();
    let mut txn = self.0.txn();
    txn.put(key, existing_bytes);
    txn.commit();
  }
}
