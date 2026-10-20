//! Check scheduling with dependency resolution.

use super::checks::ActiveCheck;
use super::policy::ScanPolicy;
use std::collections::{HashMap, HashSet};

pub struct ScanScheduler {
    checks: Vec<Box<dyn ActiveCheck>>,
}

impl ScanScheduler {
    pub fn new(checks: Vec<Box<dyn ActiveCheck>>) -> Self {
        Self { checks }
    }

    /// Schedule enabled checks in dependency order; policy-disabled checks
    /// are marked satisfied without being scheduled, so dependents still run.
    pub fn schedule_checks(&self, policy: &ScanPolicy) -> Vec<&dyn ActiveCheck> {
        let mut scheduled: Vec<&dyn ActiveCheck> = Vec::new();
        let mut completed = HashSet::new();

        // Build dependency graph, recording disabled checks as satisfied.
        let mut dependencies: HashMap<String, Vec<String>> = HashMap::new();
        for check in &self.checks {
            let id = check.id();
            if !policy.is_check_enabled(id) {
                completed.insert(id.to_string());
                continue;
            }
            dependencies.insert(
                id.to_string(),
                check.dependencies().iter().map(|s| s.to_string()).collect(),
            );
        }

        // Topological sort: dependencies maps enabled checks only, so it is
        // the target size for `scheduled`.
        while scheduled.len() < dependencies.len() {
            let mut made_progress = false;

            for check in &self.checks {
                let check_id = check.id().to_string();

                if completed.contains(&check_id) {
                    continue;
                }

                // Check if all dependencies satisfied
                let deps = dependencies.get(&check_id).unwrap();
                let ready = deps.iter().all(|dep| completed.contains(dep));

                if ready {
                    scheduled.push(check.as_ref());
                    completed.insert(check_id);
                    made_progress = true;
                }
            }

            if !made_progress {
                // Circular dependency or orphaned check - add remaining
                for check in &self.checks {
                    let check_id = check.id().to_string();
                    if !completed.contains(&check_id) {
                        scheduled.push(check.as_ref());
                        completed.insert(check_id);
                    }
                }
                break;
            }
        }

        scheduled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active_scan::checks::*;
    use crate::domain::*;
    use crate::fuzzer::variants::{InjectionPoint, VariantType};
    use async_trait::async_trait;

    struct CheckA;
    struct CheckB;
    struct CheckC;

    #[async_trait]
    impl ActiveCheck for CheckA {
        fn id(&self) -> &str {
            "a"
        }
        fn name(&self) -> &str {
            "Check A"
        }
        fn dependencies(&self) -> Vec<&str> {
            vec![]
        }
        async fn execute(
            &self,
            _job: &crate::active_scan::job::ActiveScanJob,
            _point: &InjectionPoint,
            _db: &std::sync::Arc<crate::storage::Db>,
            _reply: &std::sync::Arc<crate::reply::ReplyService>,
        ) -> DomainResult<Option<CheckResult>> {
            Ok(None)
        }
    }

    #[async_trait]
    impl ActiveCheck for CheckB {
        fn id(&self) -> &str {
            "b"
        }
        fn name(&self) -> &str {
            "Check B"
        }
        fn dependencies(&self) -> Vec<&str> {
            vec!["a"]
        }
        async fn execute(
            &self,
            _job: &crate::active_scan::job::ActiveScanJob,
            _point: &InjectionPoint,
            _db: &std::sync::Arc<crate::storage::Db>,
            _reply: &std::sync::Arc<crate::reply::ReplyService>,
        ) -> DomainResult<Option<CheckResult>> {
            Ok(None)
        }
    }

    #[async_trait]
    impl ActiveCheck for CheckC {
        fn id(&self) -> &str {
            "c"
        }
        fn name(&self) -> &str {
            "Check C"
        }
        fn dependencies(&self) -> Vec<&str> {
            vec!["a", "b"]
        }
        async fn execute(
            &self,
            _job: &crate::active_scan::job::ActiveScanJob,
            _point: &InjectionPoint,
            _db: &std::sync::Arc<crate::storage::Db>,
            _reply: &std::sync::Arc<crate::reply::ReplyService>,
        ) -> DomainResult<Option<CheckResult>> {
            Ok(None)
        }
    }

    #[test]
    fn schedule_with_dependencies() {
        let checks: Vec<Box<dyn ActiveCheck>> =
            vec![Box::new(CheckC), Box::new(CheckA), Box::new(CheckB)];

        let scheduler = ScanScheduler::new(checks);
        let policy = ScanPolicy::default();
        let scheduled = scheduler.schedule_checks(&policy);

        let ids: Vec<&str> = scheduled.iter().map(|c| c.id()).collect();

        // A must come before B, both must come before C
        let a_pos = ids.iter().position(|&id| id == "a").unwrap();
        let b_pos = ids.iter().position(|&id| id == "b").unwrap();
        let c_pos = ids.iter().position(|&id| id == "c").unwrap();

        assert!(a_pos < b_pos);
        assert!(b_pos < c_pos);
    }
}
