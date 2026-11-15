mod acceptance;
mod admission;
mod check;
mod collection;
mod consumer;
mod context;
mod frontend;
mod graph;
mod installation;
mod native;
mod output_files;
mod policy;
mod process;
mod store;
pub(crate) use frontend::{is_static, run};
mod apply_records;
mod repository;
mod source;

#[cfg(test)]
mod apply_tests;
mod git_dependency;
mod ioc_exception;
