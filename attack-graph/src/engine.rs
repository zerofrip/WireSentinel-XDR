use std::collections::{HashMap, HashSet, VecDeque};

use parking_lot::RwLock;
use shared_types::{
    AttackGraphEdge, AttackGraphEdgeKind, AttackGraphNode, AttackGraphNodeKind, AttackPath,
    LateralMovementFinding, XdrSeverity,
};
use uuid::Uuid;
use xdr_core::{XdrError, XdrResult};

struct GraphState {
    nodes: Vec<AttackGraphNode>,
    edges: Vec<AttackGraphEdge>,
}

impl Default for GraphState {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }
}

/// Attack graph engine for path discovery, blast radius, and lateral movement analysis.
pub struct AttackGraphEngine {
    state: RwLock<GraphState>,
}

impl AttackGraphEngine {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(GraphState::default()),
        }
    }

    pub fn add_node(&self, node: AttackGraphNode) -> Uuid {
        let id = node.id;
        self.state.write().nodes.push(node);
        id
    }

    pub fn add_edge(&self, edge: AttackGraphEdge) -> Uuid {
        let id = edge.id;
        self.state.write().edges.push(edge);
        id
    }

    pub fn node_count(&self) -> usize {
        self.state.read().nodes.len()
    }

    pub fn discover_paths(
        &self,
        source_id: Uuid,
        target_id: Uuid,
        max_depth: usize,
    ) -> XdrResult<Vec<AttackPath>> {
        let state = self.state.read();
        if !state.nodes.iter().any(|n| n.id == source_id) {
            return Err(XdrError::AttackGraph(format!(
                "source node {source_id} not found"
            )));
        }
        if !state.nodes.iter().any(|n| n.id == target_id) {
            return Err(XdrError::AttackGraph(format!(
                "target node {target_id} not found"
            )));
        }

        let adjacency = build_adjacency(&state.edges);
        let mut paths = Vec::new();
        let mut queue = VecDeque::new();
        queue.push_back((source_id, vec![source_id], vec![], 0.0_f64));

        while let Some((current, node_path, edge_path, risk)) = queue.pop_front() {
            if current == target_id && node_path.len() > 1 {
                paths.push(AttackPath {
                    nodes: node_path.clone(),
                    edges: edge_path.clone(),
                    risk_score: risk,
                });
                continue;
            }
            if node_path.len() > max_depth {
                continue;
            }

            if let Some(neighbors) = adjacency.get(&current) {
                for (next, edge_id, weight) in neighbors {
                    if node_path.contains(next) {
                        continue;
                    }
                    let mut np = node_path.clone();
                    np.push(*next);
                    let mut ep = edge_path.clone();
                    ep.push(*edge_id);
                    queue.push_back((*next, np, ep, risk + weight));
                }
            }
        }

        paths.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());
        Ok(paths)
    }

    pub fn blast_radius(&self, compromised_id: Uuid) -> Vec<Uuid> {
        let state = self.state.read();
        let adjacency = build_adjacency(&state.edges);
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(compromised_id);
        visited.insert(compromised_id);

        while let Some(current) = queue.pop_front() {
            if let Some(neighbors) = adjacency.get(&current) {
                for (next, _, _) in neighbors {
                    if visited.insert(*next) {
                        queue.push_back(*next);
                    }
                }
            }
        }
        visited.into_iter().collect()
    }

    pub fn lateral_movement_analysis(&self) -> Vec<LateralMovementFinding> {
        let state = self.state.read();
        let mut findings = Vec::new();

        for edge in &state.edges {
            if edge.edge_kind != AttackGraphEdgeKind::NetworkReachability {
                continue;
            }
            let source = state.nodes.iter().find(|n| n.id == edge.source_id);
            let target = state.nodes.iter().find(|n| n.id == edge.target_id);
            if let (Some(src), Some(tgt)) = (source, target) {
                if matches!(src.node_kind, AttackGraphNodeKind::Device)
                    && matches!(tgt.node_kind, AttackGraphNodeKind::Device)
                {
                    findings.push(LateralMovementFinding {
                        id: Uuid::new_v4(),
                        device_id: src.id,
                        source_host: src.label.clone(),
                        target_host: tgt.label.clone(),
                        protocol: "network".into(),
                        severity: XdrSeverity::High,
                        detected_at: chrono::Utc::now(),
                    });
                }
            }
        }
        findings
    }
}

impl Default for AttackGraphEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn build_adjacency(edges: &[AttackGraphEdge]) -> HashMap<Uuid, Vec<(Uuid, Uuid, f64)>> {
    let mut map: HashMap<Uuid, Vec<(Uuid, Uuid, f64)>> = HashMap::new();
    for edge in edges {
        map.entry(edge.source_id)
            .or_default()
            .push((edge.target_id, edge.id, edge.weight));
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn device(tenant: Uuid, label: &str) -> AttackGraphNode {
        AttackGraphNode {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            node_kind: AttackGraphNodeKind::Device,
            label: label.into(),
            metadata: serde_json::json!({}),
        }
    }

    #[test]
    fn discovers_attack_path() {
        let engine = AttackGraphEngine::new();
        let tenant = Uuid::new_v4();
        let a = device(tenant, "host-a");
        let b = device(tenant, "host-b");
        let c = device(tenant, "host-c");
        engine.add_node(a.clone());
        engine.add_node(b.clone());
        engine.add_node(c.clone());
        engine.add_edge(AttackGraphEdge {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            source_id: a.id,
            target_id: b.id,
            edge_kind: AttackGraphEdgeKind::NetworkReachability,
            weight: 1.0,
        });
        engine.add_edge(AttackGraphEdge {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            source_id: b.id,
            target_id: c.id,
            edge_kind: AttackGraphEdgeKind::NetworkReachability,
            weight: 2.0,
        });

        let paths = engine.discover_paths(a.id, c.id, 5).unwrap();
        assert!(!paths.is_empty());
        assert_eq!(paths[0].nodes.len(), 3);
    }

    #[test]
    fn computes_blast_radius() {
        let engine = AttackGraphEngine::new();
        let tenant = Uuid::new_v4();
        let a = device(tenant, "a");
        let b = device(tenant, "b");
        engine.add_node(a.clone());
        engine.add_node(b.clone());
        engine.add_edge(AttackGraphEdge {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            source_id: a.id,
            target_id: b.id,
            edge_kind: AttackGraphEdgeKind::Access,
            weight: 1.0,
        });
        let radius = engine.blast_radius(a.id);
        assert_eq!(radius.len(), 2);
    }
}
