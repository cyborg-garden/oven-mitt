//! The audit trail (PRD §6). Append-only, hash-chained JSONL; the single
//! thing that lets an operator be confident about what did and didn't
//! happen to the data. Modules arrive across M1 (`canon`) and M3 (writer,
//! verify) and M6 (review).

pub mod canon;
