// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Budget allocator for priority-based rate distribution.
//!
//! Distributes the global rate budget across writers based on priority:
//! - P0 (Critical): Protected minimum share, never starved
//! - P1 (Normal): Gets majority of remaining budget
//! - P2 (Background): Gets smallest share, first to be reduced

use std::collections::HashMap;

use super::config::Priority;

/// Unique identifier for a writer.
pub type WriterId = u64;

/// Configuration for budget allocation.
#[derive(Debug, Clone, Copy)]
pub struct AllocationConfig {
    /// Minimum share reserved for P0 (0.0 - 1.0).
    pub p0_min_share: f32,
    /// Minimum absolute budget for P0 (bytes/sec).
    pub p0_min_bps: u32,
    /// Share of remaining budget for P1 (0.0 - 1.0).
    pub p1_share: f32,
    /// Share of remaining budget for P2 (0.0 - 1.0).
    pub p2_share: f32,
    /// Minimum budget per writer (bytes/sec).
    pub min_per_writer: u32,
}

impl Default for AllocationConfig {
    fn default() -> Self {
        Self {
            p0_min_share: 0.2,    // 20% reserved for P0
            p0_min_bps: 10_000,   // 10 KB/s minimum for P0
            p1_share: 0.7,        // 70% of remaining to P1
            p2_share: 0.3,        // 30% of remaining to P2
            min_per_writer: 1000, // 1 KB/s minimum per writer
        }
    }
}

impl AllocationConfig {
    /// Create with custom P0 protection.
    pub fn with_p0_protection(mut self, share: f32, min_bps: u32) -> Self {
        self.p0_min_share = share.clamp(0.0, 1.0);
        self.p0_min_bps = min_bps;
        self
    }

    /// Create with custom P1/P2 split.
    pub fn with_split(mut self, p1_share: f32, p2_share: f32) -> Self {
        let total = p1_share + p2_share;
        if total > 0.0 {
            self.p1_share = p1_share / total;
            self.p2_share = p2_share / total;
        }
        self
    }
}

/// Information about a registered writer.
#[derive(Debug, Clone, Copy)]
pub struct WriterInfo {
    /// Writer priority.
    pub priority: Priority,
    /// Weight within priority class (default 1.0).
    pub weight: f32,
    /// Current allocated budget (bytes/sec).
    pub budget_bps: u32,
    /// Whether this writer is active.
    pub active: bool,
}

impl WriterInfo {
    /// Create a new writer info.
    pub fn new(priority: Priority) -> Self {
        Self {
            priority,
            weight: 1.0,
            budget_bps: 0,
            active: true,
        }
    }

    /// Create with custom weight.
    pub fn with_weight(priority: Priority, weight: f32) -> Self {
        Self {
            priority,
            weight: weight.max(0.1),
            budget_bps: 0,
            active: true,
        }
    }
}

/// Budget update for a writer.
#[derive(Debug, Clone, Copy)]
pub struct WriterBudgetUpdate {
    /// Writer ID.
    pub writer_id: WriterId,
    /// New budget (bytes/sec).
    pub budget_bps: u32,
    /// Previous budget (for delta calculation).
    pub previous_bps: u32,
}

impl WriterBudgetUpdate {
    /// Get the budget change (positive = increase, negative = decrease).
    pub fn delta(&self) -> i64 {
        self.budget_bps as i64 - self.previous_bps as i64
    }

    /// Check if budget increased.
    pub fn increased(&self) -> bool {
        self.budget_bps > self.previous_bps
    }

    /// Check if budget decreased.
    pub fn decreased(&self) -> bool {
        self.budget_bps < self.previous_bps
    }
}

/// Allocates budget across writers by priority.
///
/// Ensures P0 writers are protected while distributing remaining
/// budget fairly among P1 and P2 writers.
#[derive(Debug)]
pub struct BudgetAllocator {
    /// Configuration.
    config: AllocationConfig,

    /// Registered writers.
    writers: HashMap<WriterId, WriterInfo>,

    /// Current global budget.
    global_budget_bps: u32,

    /// Statistics.
    stats: AllocationStats,
}

/// Statistics for budget allocation.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllocationStats {
    /// Total reallocations performed.
    pub reallocations: u64,
    /// Writers registered.
    pub writers_registered: u64,
    /// Writers unregistered.
    pub writers_unregistered: u64,
    /// Total budget distributed (cumulative).
    pub total_distributed_bps: u64,
}

impl BudgetAllocator {
    /// Create a new budget allocator with default configuration.
    pub fn new() -> Self {
        Self::with_config(AllocationConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: AllocationConfig) -> Self {
        Self {
            config,
            writers: HashMap::new(),
            global_budget_bps: 0,
            stats: AllocationStats::default(),
        }
    }

    /// Register a writer.
    pub fn register(&mut self, writer_id: WriterId, priority: Priority) {
        self.writers.insert(writer_id, WriterInfo::new(priority));
        self.stats.writers_registered += 1;
    }

    /// Register a writer with custom weight.
    pub fn register_weighted(&mut self, writer_id: WriterId, priority: Priority, weight: f32) {
        self.writers
            .insert(writer_id, WriterInfo::with_weight(priority, weight));
        self.stats.writers_registered += 1;
    }

    /// Unregister a writer.
    pub fn unregister(&mut self, writer_id: WriterId) -> bool {
        if self.writers.remove(&writer_id).is_some() {
            self.stats.writers_unregistered += 1;
            true
        } else {
            false
        }
    }

    /// Set writer active/inactive.
    pub fn set_active(&mut self, writer_id: WriterId, active: bool) {
        if let Some(info) = self.writers.get_mut(&writer_id) {
            info.active = active;
        }
    }

    /// Update writer weight.
    pub fn set_weight(&mut self, writer_id: WriterId, weight: f32) {
        if let Some(info) = self.writers.get_mut(&writer_id) {
            info.weight = weight.max(0.1);
        }
    }

    /// Reallocate budgets after global rate change.
    ///
    /// Returns updates for all affected writers.
    pub fn reallocate(&mut self, global_rate_bps: u32) -> Vec<WriterBudgetUpdate> {
        self.global_budget_bps = global_rate_bps;
        self.stats.reallocations += 1;

        let mut updates = Vec::new();

        // Collect active writers by priority
        let p0_writers: Vec<_> = self
            .writers
            .iter()
            .filter(|(_, w)| w.priority == Priority::P0 && w.active)
            .map(|(&id, w)| (id, w.weight))
            .collect();

        let p1_writers: Vec<_> = self
            .writers
            .iter()
            .filter(|(_, w)| w.priority == Priority::P1 && w.active)
            .map(|(&id, w)| (id, w.weight))
            .collect();

        let p2_writers: Vec<_> = self
            .writers
            .iter()
            .filter(|(_, w)| w.priority == Priority::P2 && w.active)
            .map(|(&id, w)| (id, w.weight))
            .collect();

        // Calculate P0 reserve
        let p0_reserve = self.calculate_p0_reserve(global_rate_bps);

        // Distribute P0
        let p0_allocated = self.distribute_weighted(&p0_writers, p0_reserve, &mut updates);

        // Calculate remaining for P1/P2
        let remaining = global_rate_bps.saturating_sub(p0_allocated);

        // Split remaining between P1 and P2
        let p1_budget = (remaining as f32 * self.config.p1_share) as u32;
        let p2_budget = remaining.saturating_sub(p1_budget);

        // Distribute P1
        self.distribute_weighted(&p1_writers, p1_budget, &mut updates);

        // Distribute P2
        self.distribute_weighted(&p2_writers, p2_budget, &mut updates);

        // Update stored budgets
        for update in &updates {
            if let Some(info) = self.writers.get_mut(&update.writer_id) {
                info.budget_bps = update.budget_bps;
            }
        }

        // Update stats
        let total: u64 = updates.iter().map(|u| u.budget_bps as u64).sum();
        self.stats.total_distributed_bps += total;

        updates
    }

    /// Calculate P0 reserve budget.
    fn calculate_p0_reserve(&self, global_rate_bps: u32) -> u32 {
        let share_based = (global_rate_bps as f32 * self.config.p0_min_share) as u32;
        share_based.max(self.config.p0_min_bps)
    }

    /// Distribute budget among writers weighted by their weight.
    fn distribute_weighted(
        &self,
        writers: &[(WriterId, f32)],
        budget: u32,
        updates: &mut Vec<WriterBudgetUpdate>,
    ) -> u32 {
        if writers.is_empty() {
            return 0;
        }

        let total_weight: f32 = writers.iter().map(|(_, w)| w).sum();
        if total_weight <= 0.0 {
            return 0;
        }

        let mut allocated = 0u32;

        for &(writer_id, weight) in writers {
            let share = (budget as f32 * (weight / total_weight)) as u32;
            let final_budget = share.max(self.config.min_per_writer);

            let previous = self
                .writers
                .get(&writer_id)
                .map(|w| w.budget_bps)
                .unwrap_or(0);

            updates.push(WriterBudgetUpdate {
                writer_id,
                budget_bps: final_budget,
                previous_bps: previous,
            });

            allocated += final_budget;
        }

        allocated
    }

    /// Get the current budget for a writer.
    pub fn get_budget(&self, writer_id: WriterId) -> Option<u32> {
        self.writers.get(&writer_id).map(|w| w.budget_bps)
    }

    /// Get writer info.
    pub fn get_writer(&self, writer_id: WriterId) -> Option<&WriterInfo> {
        self.writers.get(&writer_id)
    }

    /// Get the number of registered writers.
    pub fn writer_count(&self) -> usize {
        self.writers.len()
    }

    /// Get the number of active writers.
    pub fn active_count(&self) -> usize {
        self.writers.values().filter(|w| w.active).count()
    }

    /// Get count by priority.
    pub fn count_by_priority(&self, priority: Priority) -> usize {
        self.writers
            .values()
            .filter(|w| w.priority == priority && w.active)
            .count()
    }

    /// Get the current global budget.
    pub fn global_budget(&self) -> u32 {
        self.global_budget_bps
    }

    /// Get total allocated budget across all writers.
    pub fn total_allocated(&self) -> u64 {
        self.writers.values().map(|w| w.budget_bps as u64).sum()
    }

    /// Get statistics.
    pub fn stats(&self) -> AllocationStats {
        self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = AllocationStats::default();
    }

    /// Get the configuration.
    pub fn config(&self) -> &AllocationConfig {
        &self.config
    }

    /// Clear all writers.
    pub fn clear(&mut self) {
        self.writers.clear();
    }
}

impl Default for BudgetAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let cfg = AllocationConfig::default();
        assert!((cfg.p0_min_share - 0.2).abs() < 0.001);
        assert_eq!(cfg.p0_min_bps, 10_000);
    }

    #[test]
    fn test_config_builder() {
        let cfg = AllocationConfig::default()
            .with_p0_protection(0.3, 20_000)
            .with_split(0.6, 0.4);

        assert!((cfg.p0_min_share - 0.3).abs() < 0.001);
        assert_eq!(cfg.p0_min_bps, 20_000);
        assert!((cfg.p1_share - 0.6).abs() < 0.001);
        assert!((cfg.p2_share - 0.4).abs() < 0.001);
    }

    #[test]
    fn test_new() {
        let alloc = BudgetAllocator::new();
        assert_eq!(alloc.writer_count(), 0);
        assert_eq!(alloc.global_budget(), 0);
    }

    #[test]
    fn test_register() {
        let mut alloc = BudgetAllocator::new();

        alloc.register(1, Priority::P0);
        alloc.register(2, Priority::P1);
        alloc.register(3, Priority::P2);

        assert_eq!(alloc.writer_count(), 3);
        assert_eq!(alloc.count_by_priority(Priority::P0), 1);
        assert_eq!(alloc.count_by_priority(Priority::P1), 1);
        assert_eq!(alloc.count_by_priority(Priority::P2), 1);
    }

    #[test]
    fn test_register_weighted() {
        let mut alloc = BudgetAllocator::new();

        alloc.register_weighted(1, Priority::P1, 2.0);
        alloc.register_weighted(2, Priority::P1, 1.0);

        let w1 = alloc.get_writer(1).unwrap();
        let w2 = alloc.get_writer(2).unwrap();

        assert!((w1.weight - 2.0).abs() < 0.001);
        assert!((w2.weight - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_unregister() {
        let mut alloc = BudgetAllocator::new();

        alloc.register(1, Priority::P0);
        assert_eq!(alloc.writer_count(), 1);

        assert!(alloc.unregister(1));
        assert_eq!(alloc.writer_count(), 0);

        assert!(!alloc.unregister(1)); // Already removed
    }

    #[test]
    fn test_set_active() {
        let mut alloc = BudgetAllocator::new();

        alloc.register(1, Priority::P0);
        assert_eq!(alloc.active_count(), 1);

        alloc.set_active(1, false);
        assert_eq!(alloc.active_count(), 0);

        alloc.set_active(1, true);
        assert_eq!(alloc.active_count(), 1);
    }

    #[test]
    fn test_reallocate_single_p0() {
        let mut alloc = BudgetAllocator::new();

        alloc.register(1, Priority::P0);

        let updates = alloc.reallocate(100_000);

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].writer_id, 1);
        // P0 gets at least p0_min_share (20%) = 20_000
        assert!(updates[0].budget_bps >= 20_000);
    }

    #[test]
    fn test_reallocate_p0_protection() {
        let mut alloc = BudgetAllocator::new();

        alloc.register(1, Priority::P0);
        alloc.register(2, Priority::P1);
        alloc.register(3, Priority::P1);

        let updates = alloc.reallocate(100_000);

        // Find P0 budget
        let p0_budget = updates
            .iter()
            .find(|u| u.writer_id == 1)
            .unwrap()
            .budget_bps;

        // P0 should get at least 20% = 20_000
        assert!(p0_budget >= 20_000);
    }

    #[test]
    fn test_reallocate_p1_p2_split() {
        let cfg = AllocationConfig::default().with_split(0.7, 0.3);
        let mut alloc = BudgetAllocator::with_config(cfg);

        alloc.register(1, Priority::P1);
        alloc.register(2, Priority::P2);

        let updates = alloc.reallocate(100_000);

        let p1_budget = updates
            .iter()
            .find(|u| u.writer_id == 1)
            .unwrap()
            .budget_bps;
        let p2_budget = updates
            .iter()
            .find(|u| u.writer_id == 2)
            .unwrap()
            .budget_bps;

        // P1 should get ~70% of total (no P0 to reserve for)
        // P2 should get ~30%
        assert!(p1_budget > p2_budget);
    }

    #[test]
    fn test_reallocate_weighted_writers() {
        let mut alloc = BudgetAllocator::new();

        // Two P1 writers with different weights
        alloc.register_weighted(1, Priority::P1, 2.0);
        alloc.register_weighted(2, Priority::P1, 1.0);

        let updates = alloc.reallocate(90_000); // 90K to avoid P0 reserve complications

        let w1_budget = updates
            .iter()
            .find(|u| u.writer_id == 1)
            .unwrap()
            .budget_bps;
        let w2_budget = updates
            .iter()
            .find(|u| u.writer_id == 2)
            .unwrap()
            .budget_bps;

        // Writer 1 should get ~2x what writer 2 gets
        let ratio = w1_budget as f32 / w2_budget as f32;
        assert!(ratio > 1.5 && ratio < 2.5);
    }

    #[test]
    fn test_reallocate_inactive_excluded() {
        let mut alloc = BudgetAllocator::new();

        alloc.register(1, Priority::P1);
        alloc.register(2, Priority::P1);

        alloc.set_active(2, false);

        let updates = alloc.reallocate(100_000);

        // Only writer 1 should get budget
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].writer_id, 1);
    }

    #[test]
    fn test_reallocate_updates_stored_budget() {
        let mut alloc = BudgetAllocator::new();

        alloc.register(1, Priority::P1);

        alloc.reallocate(100_000);

        let budget = alloc.get_budget(1).unwrap();
        assert!(budget > 0);
    }

    #[test]
    fn test_budget_update_delta() {
        let update = WriterBudgetUpdate {
            writer_id: 1,
            budget_bps: 50_000,
            previous_bps: 30_000,
        };

        assert_eq!(update.delta(), 20_000);
        assert!(update.increased());
        assert!(!update.decreased());

        let decrease = WriterBudgetUpdate {
            writer_id: 2,
            budget_bps: 20_000,
            previous_bps: 50_000,
        };

        assert_eq!(decrease.delta(), -30_000);
        assert!(!decrease.increased());
        assert!(decrease.decreased());
    }

    #[test]
    fn test_total_allocated() {
        let mut alloc = BudgetAllocator::new();

        alloc.register(1, Priority::P0);
        alloc.register(2, Priority::P1);
        alloc.register(3, Priority::P2);

        alloc.reallocate(100_000);

        let total = alloc.total_allocated();
        // Total should be close to global budget (may be slightly over due to minimums)
        assert!(total > 0);
    }

    #[test]
    fn test_stats() {
        let mut alloc = BudgetAllocator::new();

        alloc.register(1, Priority::P0);
        alloc.register(2, Priority::P1);
        alloc.unregister(2);
        alloc.reallocate(100_000);
        alloc.reallocate(50_000);

        let stats = alloc.stats();
        assert_eq!(stats.writers_registered, 2);
        assert_eq!(stats.writers_unregistered, 1);
        assert_eq!(stats.reallocations, 2);
    }

    #[test]
    fn test_clear() {
        let mut alloc = BudgetAllocator::new();

        alloc.register(1, Priority::P0);
        alloc.register(2, Priority::P1);

        alloc.clear();

        assert_eq!(alloc.writer_count(), 0);
    }

    #[test]
    fn test_minimum_per_writer() {
        let cfg = AllocationConfig {
            min_per_writer: 5000,
            ..Default::default()
        };
        let mut alloc = BudgetAllocator::with_config(cfg);

        // Register many writers
        for i in 0..10 {
            alloc.register(i, Priority::P1);
        }

        let updates = alloc.reallocate(10_000); // Very small budget

        // Each writer should get at least min_per_writer
        for update in updates {
            assert!(update.budget_bps >= 5000);
        }
    }

    #[test]
    fn test_empty_reallocate() {
        let mut alloc = BudgetAllocator::new();

        let updates = alloc.reallocate(100_000);

        assert!(updates.is_empty());
    }

    #[test]
    fn test_all_priorities() {
        let mut alloc = BudgetAllocator::new();

        alloc.register(1, Priority::P0);
        alloc.register(2, Priority::P0);
        alloc.register(3, Priority::P1);
        alloc.register(4, Priority::P1);
        alloc.register(5, Priority::P1);
        alloc.register(6, Priority::P2);

        let updates = alloc.reallocate(100_000);

        assert_eq!(updates.len(), 6);

        // P0 writers should have budget
        let p0_total: u32 = updates
            .iter()
            .filter(|u| u.writer_id <= 2)
            .map(|u| u.budget_bps)
            .sum();
        assert!(p0_total >= 20_000); // At least P0 reserve
    }

    #[test]
    fn test_p0_min_bps_floor() {
        let cfg = AllocationConfig {
            p0_min_share: 0.01, // Very small share
            p0_min_bps: 50_000, // But high minimum
            ..Default::default()
        };
        let mut alloc = BudgetAllocator::with_config(cfg);

        alloc.register(1, Priority::P0);

        let updates = alloc.reallocate(100_000);

        // Should get at least p0_min_bps regardless of share
        assert!(updates[0].budget_bps >= 50_000);
    }
}
