#[inline(always)]
pub fn name_of_params(k: u32) -> String {
    format!("K{}.params", k)
}

#[inline(always)]
pub fn name_of_solidity_aux(name: &str) -> String {
    format!("{}.aux.data", name)
}
