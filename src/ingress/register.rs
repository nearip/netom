use chrono::{DateTime, Utc};
use core::sync::atomic::AtomicU32;
use std::net::IpAddr;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::atomic::Ordering,
};

use inetnum::asn::Asn;
use paste::paste;
use routecore::bgp::message::open::Capabilities;
use routecore::bmp::message::{PeerType, RibType};
use std::fmt;
use std::sync::{Arc, RwLock};

use crate::genoutput_json;
use crate::ingress::http_ng::QueryFilter;
use crate::representation::{Cli, GenOutput, Json, OutputError};
use crate::roto_runtime::types::PeerRibType;

/// Register of ingress/sources, tracked in a serial way.
///
/// Sources are BGP sessions (so multiple per BGP connector Unit), or BMP
/// sessions (a single one per BMP connector unit), or something else.
///
/// The ingress/connector units need to register their connections with the
/// Register, providing additional information such as `SocketAddr`s or
/// string-like names. Any unit/target can query the Register.
#[derive(Debug, Default)]
pub struct Register {
    serial: AtomicU32,
    info: RwLock<HashMap<IngressId, IngressInfo>>,
}

pub type IngressId = u32;

/// Keeps a resolved path-child registered until every copy of its payload
/// has been applied or discarded. Clones share one reservation.
#[derive(Clone, Debug)]
pub struct PathChildUse(Arc<PendingPathChildUse>);

impl PathChildUse {
    pub fn ingress_id(&self) -> IngressId {
        self.0.ingress_id
    }
}

struct PendingPathChildUse {
    register: Arc<Register>,
    ingress_id: IngressId,
}

impl fmt::Debug for PendingPathChildUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PathChildUse")
            .field(&self.ingress_id)
            .finish()
    }
}

impl Drop for PendingPathChildUse {
    fn drop(&mut self) {
        let mut lock = self.register.info.write().unwrap();
        if let Some(info) = lock.get_mut(&self.ingress_id) {
            info.pending_path_uses -= 1;
        }
    }
}

/// Breakdown of the ingress register by entry state, for memory reporting.
/// Produced by [`Register::memory_summary`].
#[derive(Debug, Default, Clone, Copy)]
pub struct RegisterMemSummary {
    pub total: usize,
    pub connected: usize,
    pub disconnected: usize,
    pub non_network: usize,
    pub state_unset: usize,
    pub bgp_via_bmp: usize,
    /// ADD-PATH path-child entries (`IngressType::BgpPath`).
    pub bgp_path: usize,
    pub pending_path_uses: usize,
}

#[derive(serde::Serialize)]
pub struct IdAndInfo<'a> {
    #[serde(rename = "id")]
    pub ingress_id: IngressId,
    #[serde(flatten)]
    pub ingress_info: &'a IngressInfo,
}

#[derive(serde::Serialize)]
pub struct OwnedIdAndInfo {
    #[serde(rename = "id")]
    pub ingress_id: IngressId,
    #[serde(flatten)]
    pub ingress_info: IngressInfo,
}

impl<'a> From<(IngressId, &'a IngressInfo)> for IdAndInfo<'a> {
    fn from(value: (IngressId, &'a IngressInfo)) -> Self {
        IdAndInfo {
            ingress_id: value.0,
            ingress_info: value.1,
        }
    }
}

impl From<(IngressId, IngressInfo)> for OwnedIdAndInfo {
    fn from(value: (IngressId, IngressInfo)) -> Self {
        OwnedIdAndInfo {
            ingress_id: value.0,
            ingress_info: value.1,
        }
    }
}

pub struct BmpIdAndInfo<'a>(pub IdAndInfo<'a>);
pub struct BgpIdAndInfo<'a>(pub IdAndInfo<'a>);

impl<W: std::io::Write> GenOutput<Cli<W>> for BgpIdAndInfo<'_> {
    fn write(&self, target: &mut Cli<W>) -> Result<(), OutputError> {
        let _ = writeln!(
            &mut target.0,
            "{:>}\t{:>10}\t{:>40}",
            self.0.ingress_id,
            self.0
                .ingress_info
                .remote_asn
                .map(|asn| asn.to_string())
                .unwrap_or("no-asn???".into()),
            self.0
                .ingress_info
                .remote_addr
                .map(|ip| ip.to_string())
                .unwrap_or("no-ip".into()),
        );
        let _ = target.0.flush();
        Ok(())
    }
}

impl<W: std::io::Write> GenOutput<Cli<W>> for BmpIdAndInfo<'_> {
    fn write(&self, target: &mut Cli<W>) -> Result<(), OutputError> {
        let _ = writeln!(
            &mut target.0,
            "{:>}\t{:>40}\t{}",
            self.0.ingress_id,
            self.0
                .ingress_info
                .remote_addr
                .map(|ip| ip.to_string())
                .unwrap_or("no-ip".into()),
            self.0
                .ingress_info
                .name
                .as_ref()
                .unwrap_or(&"no-name".into())
        );
        let _ = target.0.flush();
        Ok(())
    }
}

genoutput_json!(IdAndInfo<'_>);
genoutput_json!(BmpIdAndInfo<'_>, 0);
genoutput_json!(BgpIdAndInfo<'_>, 0);

pub struct TestMe {
    field: Asn,
}
genoutput_json!(TestMe, field);

// Used to merge IngressInfo structs, called via info_for_field! in update_info
macro_rules! update_field {
    ($old:ident, $new:ident, $field:ident) => {
        if $new.$field.is_some() {
            $old.$field = $new.$field;
        }
    };
}

// Used to create the builder pattern methods, called in info_for_field!
macro_rules! with_field {
    ($name:ident, $type:ty) => {
        paste! {
            pub fn [<with_$name>](self, $name: impl Into<$type>) -> Self {
                Self {
                    $name: Some($name.into()), ..self }
            }
        }
    };
}

// Creates the IngressInfo (== $name) struct and adds fn Register::update_info
macro_rules! info_for_field{
    ($name:ident { $( $(#[$m:meta])? $field:ident : $type:ty),* } ) => {

        /// Information pertaining to an [`IngressId`]
        ///
        /// The `IngressInfo` struct is quite broad and generic in nature, featuring
        /// fields that might not make sense in all use cases. Therefore, everything
        /// is wrapped as an `Option`, giving the user (mostly connector/ingress
        /// components within Netom) the flexibilty to fill in what makes sense in
        /// their specific case.
        #[derive(Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
        #[serde_with::skip_serializing_none]
        #[derive(serde::Serialize)]
        pub struct $name {
            $(
                $(#[$m])?
                pub $field: Option<$type>,
            )*

            // Internal generation for path-child activity; not exposed in APIs.
            #[serde(skip)]
            pub(crate) path_activity: u64,
            // Protected by the register write lock, together with GC's
            // disconnected check and removal.
            #[serde(skip)]
            pub(crate) pending_path_uses: usize,
            // Stable across exporter cache eviction; changes when an ingress
            // is claimed for a new connection. Scoped to this process.
            #[serde(skip)]
            pub(crate) history_generation: u64,
            #[serde(skip)]
            pub(crate) history_revision: u64,
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                #[cfg(test)]
                crate::tests::allocations::ingress_clone();
                Self {
                    $($field: self.$field.clone(),)*
                    path_activity: self.path_activity,
                    pending_path_uses: self.pending_path_uses,
                    history_generation: self.history_generation,
                    history_revision: self.history_revision,
                }
            }
        }

        impl $name {
            $(
                with_field!($field, $type);
            )*

        }

        impl Register {
            /// Change the info related to an [`IngressId`]
            pub fn update_info(
                &self,
                id: IngressId,
                new_info: $name,
            ) -> Option<$name> {
                let mut lock = self.info.write().unwrap();

                //log::debug!("update_info for {id} with {new_info:?}");

                if let Some(mut old) = lock.remove(&id) {

                    if new_info.state == Some(IngressState::Connected)
                        && old.state != Some(IngressState::Connected) {
                        old.history_generation = old.history_generation.saturating_add(1);
                    }
                    old.history_revision = old.history_revision.saturating_add(1);

                    $(
                        update_field!(old, new_info, $field);
                    )*
                    lock.insert(id, old) // returns the replaced info
                } else {
                    lock.insert(id, new_info) // returns the replaced info
                }
            }

        }
    }
}

// Creates a boolean expression from mandatory and optional fields in [`IngressInfo`]
//
// Usage:
//
//   find_existing_for!(info, query, {mandatory_fields*}, {optional_fields*}?)
//
// Note that the set of optional_fields is optional itself.
// For all fields in mandatory_fields, we check whether the field is not None
// in the `info` we have stored, then compare it to that field in the `query`.
// For fields in the optional_fields, the check for not None is skipped, the
// the field on `info` is compared to the one on `query` regardless.
macro_rules! find_existing_for {
    (
        $info:ident, $query:ident,
        { $($mandatory_field:ident),*} $(,)?
        $({ $($optional_field:ident),*})?
    ) => {
        $(
            $info.$mandatory_field.is_some() &&
            $info.$mandatory_field == $query.$mandatory_field &&
        )*
        $(
            $(
                $info.$optional_field == $query.$optional_field &&
            )*
        )?
    true // just to fill up the last '&& _' from the repetition
    }

}

impl Register {
    /// Create a new register
    pub(crate) fn new() -> Self {
        Self {
            serial: 1.into(),
            info: RwLock::new(HashMap::new()),
        }
    }

    pub fn current_serial(&self) -> u32 {
        self.serial.load(Ordering::Relaxed)
    }

    pub fn overview(&self) -> String {
        let lock = self.info.read().unwrap();
        let mut res = String::new();
        for (id, info) in lock.iter() {
            res.push_str(&format!(
                "{id:02} {}\t\t{}\n",
                info.remote_asn
                    .map(|a| a.to_string())
                    .unwrap_or("".to_string()),
                info.remote_addr
                    .map(|a| a.to_string())
                    .unwrap_or("".to_string()),
            ));
        }
        res
    }

    /// Inspect the register synchronously without copying its entries. Keep
    /// the callback short; do not perform I/O or acquire RIB locks in it.
    pub fn with_info<T>(
        &self,
        visit: impl FnOnce(&HashMap<IngressId, IngressInfo>) -> T,
    ) -> T {
        visit(&self.info.read().unwrap())
    }

    #[cfg(test)]
    pub fn cloned_info(&self) -> HashMap<IngressId, IngressInfo> {
        self.info.read().unwrap().clone()
    }

    /// Test registration without cloning the ingress's display fields.
    pub fn contains(&self, id: IngressId) -> bool {
        self.info.read().unwrap().contains_key(&id)
    }

    /// Drop entries of a caller's `… -> IngressId` map whose id no longer
    /// exists in the register, taking the read lock once.
    ///
    /// The BMP state machine and the BGP router handler each cache
    /// `path_id -> child ingress` per peer. Once the reap retires a child
    /// (see `Rib::path_child_record_removed`) that cache entry is stale, and
    /// if its path id is never reused it would never be looked up again --
    /// it would simply sit there, growing the map for the life of the
    /// session. Callers prune periodically rather than per update.
    pub fn prune_missing<K>(&self, map: &mut HashMap<K, IngressId>) {
        let lock = self.info.read().unwrap();
        map.retain(|_, id| lock.contains_key(id));
    }

    /// Snapshot the info for just these ingresses, plus the parent each one
    /// resolves through.
    ///
    /// A route query needs the register only for the muis its own result
    /// holds, which on a collector is a few hundred entries out of a register
    /// that can hold millions -- one ADD-PATH child per `(session, path_id)`,
    /// and routers that allocate a path id per path mint one per route. A
    /// production collector was measured at 1.35M entries, where
    /// [`cloned_info`](Self::cloned_info) costs 631MB of transient allocation
    /// and 350ms *per query*, including a single-prefix lookup returning four
    /// records.
    ///
    /// Parents come along because a `BgpPath` child is attributed to its
    /// session -- see [`RouteSource::resolve`](
    /// crate::units::rib_unit::rib::RouteSource::resolve) and the
    /// `filter[ingressType]` matcher. One level is enough: children never
    /// parent other children.
    pub fn cloned_info_for(
        &self,
        ids: &HashSet<IngressId>,
    ) -> HashMap<IngressId, IngressInfo> {
        let lock = self.info.read().unwrap();
        let mut res = HashMap::with_capacity(ids.len());
        for id in ids {
            let Some(info) = lock.get(id) else { continue };
            if let Some(parent) = info.parent_ingress {
                if !ids.contains(&parent) {
                    if let Some(parent_info) = lock.get(&parent) {
                        res.insert(parent, parent_info.clone());
                    }
                }
            }
            res.insert(*id, info.clone());
        }
        res
    }

    /// Tally the register for memory reporting, locking once and counting in
    /// place (no clone of the map). Returns total entries, a breakdown by
    /// state, and the number of `BgpViaBmp` entries (the synthesized BMP peers
    /// that dominate the RIB and are the prime leak suspects).
    ///
    /// A `connected` count that keeps climbing past the number of peers that
    /// are really live is the fingerprint of the half-open-exporter leak:
    /// stuck-`Connected` entries are never GC-reclaimed.
    pub fn memory_summary(&self) -> RegisterMemSummary {
        let lock = self.info.read().unwrap();
        let mut s = RegisterMemSummary {
            total: lock.len(),
            ..Default::default()
        };
        for info in lock.values() {
            s.pending_path_uses += info.pending_path_uses;
            match info.state {
                Some(IngressState::Connected) => s.connected += 1,
                Some(IngressState::Disconnected) => s.disconnected += 1,
                Some(IngressState::NonNetwork) => s.non_network += 1,
                None => s.state_unset += 1,
            }
            if info.ingress_type == Some(IngressType::BgpViaBmp) {
                s.bgp_via_bmp += 1;
            }
            if info.ingress_type == Some(IngressType::BgpPath) {
                s.bgp_path += 1;
            }
        }
        s
    }

    pub fn bgp_neighbors<T>(&self, mut target: T) -> fmt::Result
    where
        for<'a> BgpIdAndInfo<'a>: GenOutput<T>,
    {
        for t in [IngressType::BgpViaBmp, IngressType::Bgp, IngressType::Mrt]
        {
            let res = self.search(QueryFilter {
                ingress_type: Some(t),
                ..Default::default()
            });
            for r in res {
                let _ = BgpIdAndInfo(IdAndInfo {
                    ingress_id: r.ingress_id,
                    ingress_info: &r.ingress_info,
                })
                .write(&mut target);
            }
        }
        Ok(())
    }

    pub fn real_bgp_peers<T>(&self, mut target: T) -> fmt::Result
    where
        for<'a> BgpIdAndInfo<'a>: GenOutput<T>,
    {
        let res = self.search(QueryFilter {
            ingress_type: Some(IngressType::Bgp),
            ingress_state: Some(IngressState::Connected),
            ..Default::default()
        });
        for r in res {
            let _ = BgpIdAndInfo(IdAndInfo {
                ingress_id: r.ingress_id,
                ingress_info: &r.ingress_info,
            })
            .write(&mut target);
        }
        Ok(())
    }

    pub fn bmp_routers<T>(&self, mut target: T) -> fmt::Result
    where
        for<'a> BmpIdAndInfo<'a>: GenOutput<T>,
    {
        let res = self.search(QueryFilter {
            ingress_type: Some(IngressType::Bmp),
            ingress_state: Some(IngressState::Connected),
            ..Default::default()
        });
        for r in res {
            let _ = BmpIdAndInfo(IdAndInfo {
                ingress_id: r.ingress_id,
                ingress_info: &r.ingress_info,
            })
            .write(&mut target);
        }
        Ok(())
    }

    /// Request a new, unique [`IngressId`]
    pub(crate) fn register(&self) -> IngressId {
        self.serial.fetch_add(1, Ordering::Relaxed)
    }

    /// Retrieve the information for the given [`IngressId`]
    pub fn get(&self, id: IngressId) -> Option<IngressInfo> {
        self.info.read().unwrap().get(&id).cloned()
    }

    /// Borrow compact route/session identity under one register lock. The
    /// callback must not call back into the register. Avoids cloning a wide
    /// IngressInfo on every exported observation, including ADD-PATH children.
    pub(crate) fn with_history_info<R>(
        &self,
        id: IngressId,
        f: impl FnOnce(
            IngressId,
            Option<u32>,
            Option<&IngressInfo>,
            Option<&IngressInfo>,
        ) -> R,
    ) -> R {
        let lock = self.info.read().unwrap();
        let child = lock.get(&id);
        let is_path = child
            .is_some_and(|i| i.ingress_type == Some(IngressType::BgpPath));
        let session = if is_path {
            child.and_then(|i| i.parent_ingress).unwrap_or(id)
        } else {
            id
        };
        let info = lock.get(&session);
        let router = info
            .and_then(|i| i.parent_ingress)
            .and_then(|id| lock.get(&id));
        f(
            session,
            if is_path {
                child.and_then(|i| i.path_id)
            } else {
                None
            },
            info,
            router,
        )
    }

    /// Return the small identity subset used by route validation without
    /// cloning the complete ingress record (capabilities and strings).
    pub fn bgp_id_and_remote_asn(
        &self,
        id: IngressId,
    ) -> (Option<[u8; 4]>, Option<Asn>) {
        self.info
            .read()
            .unwrap()
            .get(&id)
            .map(|info| (info.bgp_id, info.remote_asn))
            .unwrap_or((None, None))
    }

    /// Resolve an ADD-PATH path-child mui (`IngressType::BgpPath`) to its
    /// parent session's ingress id; any other id is returned unchanged.
    ///
    /// All paths of one ADD-PATH session belong to the same peer, but the
    /// child entries carry only display fields — anything comparing peer
    /// identity across muis (RFC 8955 §6 flowspec validation) must resolve
    /// children to their session first or two paths of one peer look like
    /// two different peers.
    pub fn session_for(&self, id: IngressId) -> IngressId {
        self.info
            .read()
            .unwrap()
            .get(&id)
            .filter(|info| info.ingress_type == Some(IngressType::BgpPath))
            .and_then(|info| info.parent_ingress)
            .unwrap_or(id)
    }

    /// Retrieve the information for the given [`IngressId`]
    pub fn get_tuple(&self, id: IngressId) -> Option<OwnedIdAndInfo> {
        self.info
            .read()
            .unwrap()
            .get(&id)
            .map(|info| (id, info.clone()).into())
    }

    /// Stream in the register's existing iteration order. Only the IDs are
    /// snapshotted; each record is serialized while borrowed, then the lock is
    /// released before writing to the potentially network-paced target.
    pub fn write_search<W: std::io::Write>(
        &self,
        filter: QueryFilter,
        target: &mut W,
    ) -> Result<(), OutputError> {
        use crate::representation::OutputFormat;
        let ids: Vec<_> = self.with_info(|info| {
            info.iter()
                .filter(|(_, i)| filter.filter(i))
                .map(|(&id, _)| id)
                .collect()
        });
        let json = filter.format == OutputFormat::Json;
        if json {
            target.write_all(b"{\"data\":[")?;
        }
        let mut first = true;
        let mut line = Vec::new();
        for id in ids {
            line.clear();
            let found = self.with_info(|info| {
                if let Some(info) = info.get(&id) {
                    serde_json::to_writer(
                        &mut line,
                        &IdAndInfo::from((id, info)),
                    )?;
                    Ok::<_, serde_json::Error>(true)
                } else {
                    Ok(false)
                }
            })?;
            if !found {
                continue;
            }
            if json && !first {
                target.write_all(b",")?;
            }
            target.write_all(&line)?;
            if !json {
                target.write_all(b"\n")?;
            }
            first = false;
        }
        if json {
            target.write_all(b"]}")?;
        }
        Ok(())
    }

    /// Filter all ingresses based on a passed filter and return them
    pub fn search(&self, filter: QueryFilter) -> Vec<OwnedIdAndInfo> {
        // ALternatively, simply clone the entire thing and release the read-lock asap.
        //let mut reg = self.info.read().unwrap().clone();

        self.info
            .read()
            .unwrap()
            .iter()
            .filter(|(_, info)| filter.filter(info))
            .map(|(&ingress_id, info)| OwnedIdAndInfo {
                ingress_id,
                ingress_info: info.clone(),
            })
            .collect::<Vec<_>>()
    }

    /// Filter all ingresses based on a passed filter and write it out
    pub fn search_and_output<T>(
        &self,
        filter: QueryFilter,
        mut target: T,
    ) -> Result<(), OutputError>
    where
        for<'a> IdAndInfo<'a>: GenOutput<T>,
    {
        IdAndInfo::write_seq_start(&mut target)?;
        let ids: Vec<_> = self.with_info(|all| {
            all.iter()
                .filter(|(_, info)| filter.filter(info))
                .map(|(&id, _)| id)
                .collect()
        });
        let mut first = true;
        for id in ids {
            let Some(info) = self.get(id) else {
                continue;
            };
            if !first {
                IdAndInfo::write_seq_sep(&mut target)?;
            }
            let result = IdAndInfo::from((id, &info)).write(&mut target);
            if !first {
                result?;
            }
            first = false;
        }

        IdAndInfo::write_seq_end(&mut target)?;

        Ok(())
    }

    /// Remove an ingress entry from the register
    ///
    /// Returns the [`IngressInfo`] if the entry existed, `None` otherwise.
    pub fn remove(&self, id: IngressId) -> Option<IngressInfo> {
        self.info.write().unwrap().remove(&id)
    }

    /// Remove an ingress entry only if it is currently `Disconnected`.
    ///
    /// Returns the removed [`IngressInfo`] when the entry was present and in
    /// the `Disconnected` state with no pending path users, or `None`
    /// otherwise. The pending-use check, state check and removal share a write
    /// lock, so this is the safe reclaim step for a snapshot-then-remove GC
    /// sweep: a peer that reconnected and flipped its id back to `Connected`
    /// in the window since the snapshot is left untouched, rather than having
    /// its live registration deleted out from under it.
    pub fn remove_if_disconnected(
        &self,
        id: IngressId,
    ) -> Option<IngressInfo> {
        let mut lock = self.info.write().unwrap();
        match lock.get(&id) {
            Some(info)
                if info.state == Some(IngressState::Disconnected)
                    && info.pending_path_uses == 0 =>
            {
                lock.remove(&id)
            }
            _ => None,
        }
    }

    /// Search for an existing BGP session by remote address, ASN, and ingress type
    ///
    /// Unlike [`find_existing_peer`], this does not require `parent_ingress`
    /// (which BGP sessions don't have). It matches on `remote_addr`,
    /// `remote_asn`, and `ingress_type`. Claims the entry under the write
    /// lock so GC cannot reclaim it while the session is being negotiated.
    pub fn find_existing_bgp_session_and_claim(
        &self,
        query: &IngressInfo,
    ) -> Option<(IngressId, IngressInfo)> {
        let mut lock = self.info.write().unwrap();
        for (id, info) in lock.iter_mut() {
            if find_existing_for!(info, query,
                {remote_addr, remote_asn, ingress_type},
            ) {
                info.state = Some(IngressState::Connected);
                info.history_generation =
                    info.history_generation.saturating_add(1);
                info.history_revision =
                    info.history_revision.saturating_add(1);
                return Some((*id, info.clone()));
            }
        }
        None
    }

    /// Mark an existing ingress down without resurrecting a GC'd child
    /// that remains in an input handler's cache until its next prune.
    pub fn mark_disconnected(&self, id: IngressId) -> bool {
        let mut lock = self.info.write().unwrap();
        let Some(info) = lock.get_mut(&id) else {
            return false;
        };
        info.state = Some(IngressState::Disconnected);
        info.history_revision = info.history_revision.saturating_add(1);
        true
    }

    /// Whether `id` is an ADD-PATH path-child. A read, no clone.
    pub fn is_path_child(&self, id: IngressId) -> bool {
        self.info
            .read()
            .unwrap()
            .get(&id)
            .is_some_and(|i| i.ingress_type == Some(IngressType::BgpPath))
    }

    /// Retire a connected path-child that owns no record any more: it goes
    /// `Disconnected` and the GC reclaims its entry. Returns whether it did.
    pub fn retire_empty_path_child(&self, id: IngressId) -> bool {
        let mut lock = self.info.write().unwrap();
        let Some(info) = lock.get_mut(&id) else {
            return false;
        };
        if info.ingress_type != Some(IngressType::BgpPath)
            || info.state != Some(IngressState::Connected)
        {
            return false;
        }
        info.state = Some(IngressState::Disconnected);
        info.history_revision = info.history_revision.saturating_add(1);
        true
    }

    /// Undo `retire_empty_path_child` for a child that owns a record again:
    /// it goes back to `Connected` so the GC leaves it alone. Returns
    /// whether it did; `false` when the child is already connected or no
    /// longer registered.
    ///
    /// The RIB unit runs behind the BMP unit, which refreshes a cached
    /// child when it explodes an announcement (`reserve_path_child`). When
    /// a withdrawal that empties the child and an announcement under the
    /// same path id are exploded back to back, that refresh lands before
    /// the RIB retires the child, and only the RIB, when it then adds the
    /// record, knows the child is live again.
    pub fn reconnect_path_child(&self, id: IngressId) -> bool {
        let mut lock = self.info.write().unwrap();
        let Some(info) = lock.get_mut(&id) else {
            return false;
        };
        if info.ingress_type != Some(IngressType::BgpPath)
            || info.state != Some(IngressState::Disconnected)
        {
            return false;
        }
        info.state = Some(IngressState::Connected);
        info.history_generation = info.history_generation.saturating_add(1);
        info.history_revision = info.history_revision.saturating_add(1);
        true
    }

    /// Validate a cached path-child and reactivate it atomically with GC.
    /// Recording activity also invalidates any in-progress idle scan.
    pub fn refresh_path_child(
        &self,
        id: IngressId,
        parent: IngressId,
        path_id: u32,
    ) -> bool {
        let mut lock = self.info.write().unwrap();
        let Some(info) = lock.get_mut(&id) else {
            return false;
        };
        if info.ingress_type != Some(IngressType::BgpPath)
            || info.parent_ingress != Some(parent)
            || info.path_id != Some(path_id)
        {
            return false;
        }
        info.path_activity = info.path_activity.saturating_add(1);
        info.state = Some(IngressState::Connected);
        true
    }

    /// Validate, refresh and reserve a cached child under the same lock
    /// used by GC. No disconnected child can disappear between resolution
    /// and the payload's eventual insertion and record accounting.
    pub fn reserve_path_child(
        self: &Arc<Self>,
        id: IngressId,
        parent: IngressId,
        path_id: u32,
    ) -> Option<PathChildUse> {
        let mut lock = self.info.write().unwrap();
        let info = lock.get_mut(&id)?;
        if info.ingress_type != Some(IngressType::BgpPath)
            || info.parent_ingress != Some(parent)
            || info.path_id != Some(path_id)
        {
            return None;
        }
        info.pending_path_uses += 1;
        info.path_activity = info.path_activity.saturating_add(1);
        info.state = Some(IngressState::Connected);
        Some(PathChildUse(Arc::new(PendingPathChildUse {
            register: self.clone(),
            ingress_id: id,
        })))
    }

    /// Find all [`IngressId`]s that are children of the given `parent`
    ///
    /// This is used in cases where for example a BMP session (the parent) is
    /// terminated, and all route information that was learned for that
    /// session (in one or multiple monitored BGP sessions, the children) need
    /// to be withdrawn.
    pub fn ids_for_parent(&self, parent: IngressId) -> Vec<IngressId> {
        let mut res = Vec::new();
        for (id, info) in self.info.read().unwrap().iter() {
            if info.parent_ingress == Some(parent) {
                res.push(*id);
            }
        }
        res
    }

    // find_existing methods:
    // cases to cover:
    //  * match MRT update messages (to ingresses from bdumps):
    //    * from bdump, we have:
    //      * filename, remote addr, remote_asn
    //
    //  * match reconnecting BMP session:
    //      * previous BMP session had ingress_id + remote_addr
    //      * child BGP sessions had their own ingress_id + parent_id + remote
    //      addr + remote asn
    //  * match BGP flap:
    //     * previous had ingress_id + fake name + remote addr + remote asn
    //
    //
    //  do we need to register the unit name (e.g. bmp-in, mrt-in) as well?

    /// Search existing [`IngressId`] on the peer level
    ///
    /// For the peer level, the comparison is based on the parent
    /// `ingress_id`, the remote address and ASN (all three must be set).
    /// Furthermore, the RIB type, Peer type, and the Peer Distinguisher are compared, though these
    /// might be unset, i.e. None.
    pub fn find_existing_peer(
        &self,
        query: &IngressInfo,
    ) -> Option<(IngressId, IngressInfo)> {
        let lock = self.info.read().unwrap();
        for (id, info) in lock.iter() {
            // Only rebind to a Disconnected peer: a Connected entry belongs to
            // a peer that is currently up (in this or a stale session), and
            // reusing its mui would let two live peers write the same RIB
            // records. Legitimate reuse (a flapped peer within a session, or a
            // peer of a reconnected session) always finds the prior entry in
            // the Disconnected state.
            if info.state == Some(IngressState::Connected) {
                continue;
            }
            // peer_rib_type discriminates pre-policy vs post-policy variants
            // of the same (peer_addr, peer_asn). Without it, a BMP exporter
            // sending both pre- and post-policy Adj-RIB-In for the same peer
            // would collapse into a single ingress_id and routes would
            // alternately overwrite each other in the RIB.
            if find_existing_for!(info, query,
                {parent_ingress, remote_addr, remote_asn},
                {rib_type, peer_rib_type, peer_type, distinguisher, vrf_name}
            ) {
                //log::debug!("found existing peer, id {id}");
                return Some((*id, info.clone()));
            }
        }
        None
    }

    /// Like [`find_existing_peer`](Self::find_existing_peer), but atomically
    /// *claims* the matched entry by flipping it to `Connected` under a single
    /// write lock before returning it.
    ///
    /// This closes the find-then-`update_info` TOCTOU window: two concurrent
    /// reconnects of the same peer (independent per-connection tasks sharing
    /// one register) can otherwise both observe the same `Disconnected` entry
    /// — the read-time `Connected` guard cannot prevent the double-claim —
    /// and bind to one mui, so their routes overwrite each other in the RIB.
    /// With the claim, the first caller flips the entry to `Connected`; the
    /// second sees it `Connected`, skips it, and registers a fresh id. The
    /// caller is still expected to follow up with `update_info` to merge the
    /// richer PeerUp details onto the (now reserved) entry.
    pub fn find_existing_peer_and_claim(
        &self,
        query: &IngressInfo,
    ) -> Option<(IngressId, IngressInfo)> {
        let mut lock = self.info.write().unwrap();
        for (id, info) in lock.iter_mut() {
            if info.state == Some(IngressState::Connected) {
                continue;
            }
            if find_existing_for!(info, query,
                {parent_ingress, remote_addr, remote_asn},
                {rib_type, peer_rib_type, peer_type, distinguisher, vrf_name}
            ) {
                info.state = Some(IngressState::Connected);
                info.history_generation =
                    info.history_generation.saturating_add(1);
                info.history_revision =
                    info.history_revision.saturating_add(1);
                return Some((*id, info.clone()));
            }
        }
        None
    }

    /// Search existing [`IngressId`] on the BMP router leven
    ///
    /// For the BMP router level, the comparison is based on the parent
    /// `ingress_id` and the remote address (both must be set).
    ///
    /// The `name` (sysName) is included so that multiple BMP exporters
    /// connecting from the same remote IP address (e.g. behind a NAT) are kept
    /// distinct. The query's `name` is only known once the Initiation message
    /// has been parsed, so this is called from the `Initiating` state handler
    /// (not at TCP-accept). Exporters that send no sysName share the
    /// "no-sysname" sentinel, falling back to remote-address matching.
    ///
    /// Atomically *claims* the matched entry by flipping it to `Connected`
    /// under a single write lock before returning it, closing the
    /// find-then-`update_info` TOCTOU window (see
    /// [`find_existing_peer_and_claim`](Self::find_existing_peer_and_claim)):
    /// two simultaneous reconnects of the same router would otherwise both
    /// adopt one id, and the first to tear down would withdraw the live
    /// session's routes and unmap the shared id.
    pub fn find_existing_bmp_router_and_claim(
        &self,
        query: &IngressInfo,
    ) -> Option<(IngressId, IngressInfo)> {
        let mut lock = self.info.write().unwrap();
        log::debug!("query: {query:?}");
        for (id, info) in lock.iter_mut() {
            // Never adopt an id that is still Connected: another (possibly
            // stale half-open) session is using it. Reusing it would put two
            // live sessions on one id, and the stale session's teardown would
            // later withdraw the live one's routes and unmap it. A stale
            // session must drop to Disconnected before its id can be reused.
            if info.state == Some(IngressState::Connected) {
                continue;
            }
            if find_existing_for!(info, query,
                {parent_ingress, remote_addr, ingress_type},
                {name}
            ) {
                log::debug!("found matching bmp router, id {id}");
                info.state = Some(IngressState::Connected);
                info.history_generation =
                    info.history_generation.saturating_add(1);
                info.history_revision =
                    info.history_revision.saturating_add(1);
                return Some((*id, info.clone()));
            }
        }
        log::debug!("no match in find_existing_bmp_router");
        None
    }
}

impl IngressInfo {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub enum IngressType {
    Bmp,
    BgpViaBmp,
    Bgp,
    Mrt,
    Rtr,
    /// Per-path child of a BGP peer with ADD-PATH (RFC 7911) enabled.
    ///
    /// Each distinct `(peer, path_id)` pair gets its own ingress id so
    /// the RIB (keyed on `(prefix, mui)`) can hold multiple paths for one
    /// prefix from one peer. `parent_ingress` is the peer's ingress id — a
    /// `BgpViaBmp`, `Bgp`, or `Mrt` entry whose own type disambiguates origin —
    /// and `path_id` holds the RFC 7911 path identifier. Children are never
    /// downstream peers themselves: bmp-out resolves them back to the parent
    /// session for the per-peer header and re-attaches the path id when
    /// encoding NLRI.
    BgpPath,
}

#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum IngressState {
    Connected,
    Disconnected,
    NonNetwork,
}

// TODO this probably needs a 'state' (connected, disconnected, ..) ?
// and with that, a last_active timestamp/Instant
// This constructs the [`IngressInfo`] struct, used as values in the Register.
info_for_field!(IngressInfo{
   unit_name: String,
   ingress_type: IngressType,
   parent_ingress: IngressId,
   state: IngressState,
   remote_addr: IpAddr,
   remote_asn: Asn,
   bgp_id: [u8; 4],    // peer's BGP Identifier / router-id (often a loopback)
   local_addr: IpAddr, // local end of the BGP session (monitored router side)
   peer_hostname: String, // peer's hostname from BGP FQDN capability (73), if advertised
   peer_software_version: String, // peer's BGP Software Version capability (75), if advertised
   peer_role: u8,         // peer's BGP Role capability (9, RFC 9234): 0=Provider 1=RS 2=RS-Client 3=Customer 4=Peer
   session_up_time: DateTime<Utc>, // PeerUp per-peer-header timestamp (BGP session establishment time)
   rib_type: RibType,
   peer_rib_type: PeerRibType, // RibType + pre/post policy
   filename: PathBuf,
   name: String,
   desc: String,
   local_asn: Asn,
   peer_type: PeerType,
   distinguisher: [u8; 8],
   vrf_name: String,
   #[serde(serialize_with = "serialize_capability_names")]
   local_capabilities: Vec<u8>,
   #[serde(serialize_with = "serialize_capability_names")]
   remote_capabilities: Vec<u8>,
   path_id: u32, // RFC 7911 path identifier; set on IngressType::BgpPath children only
   // ADD-PATH capability (69) *value* bytes for the families the session
   // actually parses with path ids: per family AFI(u16 BE) + SAFI(u8) +
   // direction(u8). Set on *session* ingresses, derived from the session's
   // SessionConfig::enabled_addpaths() (the negotiated set), not from
   // remote_capabilities (which is one side's OPEN, not the intersection).
   #[serde(serialize_with = "serialize_addpath_families")]
   addpath_families: Vec<u8>
});

/// Serialize a raw BGP capability blob (`capabilities_as_vec` wire format) as
/// a human-readable list of capability names, e.g.
/// `["MultiProtocol","FourOctetAsn","AddPath"]`, for the `/ingresses` dump.
/// Storing the compact bytes keeps per-peer memory small; the names are
/// derived only on serialization.
fn serialize_capability_names<S>(
    caps: &Option<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let blob = caps.as_deref().unwrap_or(&[]);
    let names: Vec<String> = Capabilities(blob)
        .iter()
        .map(|c| c.typ().to_string())
        .collect();
    let mut seq = serializer.serialize_seq(Some(names.len()))?;
    for name in &names {
        seq.serialize_element(name)?;
    }
    seq.end()
}

impl crate::metrics::Source for Register {
    /// Register-population gauges, one per lifecycle/type bucket that
    /// matters operationally: total entries, connected/disconnected split
    /// (a runaway disconnected count means GC is not keeping up), and the
    /// ADD-PATH path-child population (each holds RIB records under its
    /// own mui, so this scales route memory).
    fn append(&self, unit_name: &str, target: &mut crate::metrics::Target) {
        use crate::metrics::{Metric, MetricType, MetricUnit};

        const TOTAL: Metric = Metric::new(
            "ingress_register_entries",
            "the number of entries in the global ingress register",
            MetricType::Gauge,
            MetricUnit::Total,
        );
        const CONNECTED: Metric = Metric::new(
            "ingress_register_connected",
            "ingress register entries in the Connected state",
            MetricType::Gauge,
            MetricUnit::Total,
        );
        const DISCONNECTED: Metric = Metric::new(
            "ingress_register_disconnected",
            "ingress register entries in the Disconnected state (kept for mui reuse until GC reclaims them)",
            MetricType::Gauge,
            MetricUnit::Total,
        );
        const BGP_PATH: Metric = Metric::new(
            "ingress_register_addpath_path_children",
            "ADD-PATH (RFC 7911) path-child ingresses currently in the register",
            MetricType::Gauge,
            MetricUnit::Total,
        );

        let s = self.memory_summary();
        target.append_simple(&TOTAL, Some(unit_name), s.total);
        target.append_simple(&CONNECTED, Some(unit_name), s.connected);
        target.append_simple(&DISCONNECTED, Some(unit_name), s.disconnected);
        target.append_simple(&BGP_PATH, Some(unit_name), s.bgp_path);
    }
}

/// Serialize ADD-PATH capability value bytes (per family: AFI u16 BE, SAFI
/// u8, direction u8) as a human-readable list for the `/ingresses` dump,
/// e.g. `["Ipv4Unicast/SendReceive"]`. Malformed trailing bytes render as
/// `"invalid"` rather than failing serialization.
fn serialize_addpath_families<S>(
    caps: &Option<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let blob = caps.as_deref().unwrap_or(&[]);
    let mut names = Vec::new();
    for quad in blob.chunks(4) {
        if let [afi_hi, afi_lo, safi, dir] = *quad {
            let fam = routecore::bgp::types::AfiSafiType::from((
                u16::from_be_bytes([afi_hi, afi_lo]),
                safi,
            ));
            let dir = match dir {
                1 => "Receive",
                2 => "Send",
                3 => "SendReceive",
                _ => "invalid",
            };
            names.push(format!("{fam}/{dir}"));
        } else {
            names.push("invalid".into());
        }
    }
    let mut seq = serializer.serialize_seq(Some(names.len()))?;
    for name in &names {
        seq.serialize_element(name)?;
    }
    seq.end()
}

#[cfg(test)]
mod tests {
    #[test]
    fn memory_ingress_stream_matches_legacy_bytes_without_buffering_body() {
        use crate::{
            representation::OutputFormat, tests::allocations::measure,
        };
        let register = Register::new();
        for n in 0..4096 {
            let id = register.register();
            register.update_info(
                id,
                IngressInfo::new()
                    .with_name(format!("peer {n} \"\\\n{}", "x".repeat(2048)))
                    .with_ingress_type(IngressType::Bgp)
                    .with_remote_asn(Asn::from_u32(64500 + n % 2)),
            );
        }
        for format in [OutputFormat::Json, OutputFormat::Jsonl] {
            for remote_asn in
                [None, Some(Asn::from_u32(64500)), Some(Asn::from_u32(1))]
            {
                let filter = QueryFilter {
                    format,
                    remote_asn,
                    ..Default::default()
                };
                let (expected, before) = measure(|| {
                    let mut out = Vec::new();
                    if format == OutputFormat::Json {
                        out.extend_from_slice(b"{\"data\":");
                        register.with_info(|all| {
                            out.push(b'[');
                            let mut first = true;
                            for (&id, info) in all
                                .iter()
                                .filter(|(_, info)| filter.filter(info))
                            {
                                if !first {
                                    out.push(b',');
                                }
                                serde_json::to_writer(
                                    &mut out,
                                    &IdAndInfo::from((id, info)),
                                )
                                .unwrap();
                                first = false;
                            }
                            out.push(b']');
                        });
                        out.push(b'}');
                    } else {
                        register.with_info(|all| {
                            for (&id, info) in all
                                .iter()
                                .filter(|(_, info)| filter.filter(info))
                            {
                                serde_json::to_writer(
                                    &mut out,
                                    &IdAndInfo::from((id, info)),
                                )
                                .unwrap();
                                out.push(b'\n');
                            }
                        });
                    }
                    out
                });
                struct Compare<'a> {
                    register: &'a Register,
                    remaining: &'a [u8],
                }
                impl std::io::Write for Compare<'_> {
                    fn write(
                        &mut self,
                        bytes: &[u8],
                    ) -> std::io::Result<usize> {
                        // Any lock held during a downstream write is a regression.
                        assert!(self.register.info.try_write().is_ok());
                        assert!(self.remaining.starts_with(bytes));
                        self.remaining = &self.remaining[bytes.len()..];
                        Ok(bytes.len())
                    }
                    fn flush(&mut self) -> std::io::Result<()> {
                        Ok(())
                    }
                }
                let mut target = Compare {
                    register: &register,
                    remaining: &expected,
                };
                let (_, after) = measure(|| {
                    register
                        .write_search(filter.clone(), &mut target)
                        .map_err(|_| ())
                        .unwrap()
                });
                assert!(target.remaining.is_empty());
                assert_eq!(after.ingress_clones, 0);
                if remote_asn.is_none() {
                    assert!(after.peak_bytes < before.peak_bytes / 20);
                    eprintln!("ingress {format:?}: body={} bytes; peak {} -> {} bytes; clones={}",
                        expected.len(), before.peak_bytes, after.peak_bytes, after.ingress_clones);
                }
            }
        }
    }

    use super::*;

    #[test]
    fn pending_path_use_blocks_gc_until_the_last_payload_copy_is_dropped() {
        let reg = Arc::new(Register::new());
        let parent = reg.register();
        let child = reg.register();
        reg.update_info(
            child,
            IngressInfo::new()
                .with_ingress_type(IngressType::BgpPath)
                .with_parent_ingress(parent)
                .with_path_id(77u32)
                .with_state(IngressState::Connected),
        );
        assert!(reg.reserve_path_child(child, parent, 88).is_none());
        let pending = reg.reserve_path_child(child, parent, 77).unwrap();
        let copy = pending.clone();
        let another = reg.reserve_path_child(child, parent, 77).unwrap();
        assert_eq!(reg.memory_summary().pending_path_uses, 2);
        assert!(reg.retire_empty_path_child(child));
        assert!(reg.remove_if_disconnected(child).is_none());
        drop(pending);
        drop(another);
        assert_eq!(reg.memory_summary().pending_path_uses, 1);
        assert!(reg.remove_if_disconnected(child).is_none());
        drop(copy);
        assert_eq!(reg.memory_summary().pending_path_uses, 0);
        assert!(reg.remove_if_disconnected(child).is_some());
        assert!(reg.reserve_path_child(child, parent, 77).is_none());
    }

    #[test]
    fn builder_and_update() {
        let res = Register::new();
        let id = res.register();
        let info = IngressInfo::new().with_local_asn(Asn::from_u32(65536));
        assert_eq!(info.local_asn, Some(Asn::from_u32(65536)));

        res.update_info(id, info.clone());
        assert_eq!(res.get(id), Some(info));

        let mut newinfo =
            IngressInfo::new().with_local_asn(Asn::from_u32(65537));
        res.update_info(id, newinfo.clone());
        newinfo.history_revision = 1;
        assert_eq!(res.get(id), Some(newinfo));

        let newinfo_2 = IngressInfo::new().with_rib_type(RibType::LocRib);
        res.update_info(id, newinfo_2.clone());

        // We still expect the ASN, untouched:
        assert_eq!(
            res.get(id).unwrap().local_asn,
            Some(Asn::from_u32(65537))
        );

        // And the newly set RibType
        assert_eq!(res.get(id).unwrap().rib_type, Some(RibType::LocRib));
    }

    #[test]
    fn cloned_info_for_takes_the_ids_and_their_parents() {
        let register = Register::new();

        let session = register.register();
        register.update_info(
            session,
            IngressInfo::new().with_ingress_type(IngressType::Bgp),
        );
        let child = register.register();
        register.update_info(
            child,
            IngressInfo::new()
                .with_ingress_type(IngressType::BgpPath)
                .with_parent_ingress(session)
                .with_path_id(1u32),
        );
        let bystander = register.register();
        register.update_info(
            bystander,
            IngressInfo::new().with_ingress_type(IngressType::Bgp),
        );

        // A child drags its session in, so the record can still be
        // attributed to the peer that sent it.
        let res = register.cloned_info_for(&HashSet::from([child]));
        let mut ids: Vec<_> = res.keys().copied().collect();
        ids.sort();
        assert_eq!(ids, vec![session, child]);
        assert_eq!(res[&child].path_id, Some(1));

        // Nothing else comes along for the ride.
        assert!(!res.contains_key(&bystander));

        // An id the register does not know is skipped, not an error: a
        // record can outlive its ingress entry.
        let res =
            register.cloned_info_for(&HashSet::from([session, u32::MAX]));
        assert_eq!(res.keys().copied().collect::<Vec<_>>(), vec![session]);

        assert!(register.cloned_info_for(&HashSet::new()).is_empty());
    }

    #[test]
    fn non_mandatory_unset() {
        let res = Register::new();
        let parent_id1 = res.register();
        let session_id1_a = res.register();

        let info1_a = IngressInfo::new()
            .with_parent_ingress(parent_id1)
            .with_remote_addr("1.2.3.4".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65000));

        res.update_info(session_id1_a, info1_a.clone());

        let query1 = IngressInfo::new()
            .with_parent_ingress(parent_id1)
            .with_remote_addr("1.2.3.4".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65000));
        assert_eq!(
            res.find_existing_peer(&query1),
            Some((session_id1_a, info1_a))
        );
    }

    #[test]
    fn non_mandatory_set() {
        let res = Register::new();
        let parent_id1 = res.register();
        let session_id1_a = res.register();

        let info1_a = IngressInfo::new()
            .with_parent_ingress(parent_id1)
            .with_peer_type(PeerType::GlobalInstance)
            .with_remote_addr("1.2.3.4".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65000));

        res.update_info(session_id1_a, info1_a.clone());

        let query1 = IngressInfo::new()
            .with_parent_ingress(parent_id1)
            .with_peer_type(PeerType::GlobalInstance)
            .with_remote_addr("1.2.3.4".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65000));
        assert_eq!(
            res.find_existing_peer(&query1),
            Some((session_id1_a, info1_a))
        );
    }

    #[test]
    fn non_mandatory_query_missing_optional() {
        let res = Register::new();
        let parent_id1 = res.register();
        let session_id1_a = res.register();

        let info1_a = IngressInfo::new()
            .with_parent_ingress(parent_id1)
            .with_peer_type(PeerType::GlobalInstance)
            .with_remote_addr("1.2.3.4".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65000));

        res.update_info(session_id1_a, info1_a.clone());

        let query1 = IngressInfo::new()
            .with_parent_ingress(parent_id1)
            .with_remote_addr("1.2.3.4".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65000));
        assert_eq!(res.find_existing_peer(&query1), None,);
    }

    #[test]
    fn remove_existing() {
        let res = Register::new();
        let id = res.register();
        let info = IngressInfo::new().with_local_asn(Asn::from_u32(65536));
        res.update_info(id, info.clone());
        assert!(res.get(id).is_some());

        let removed = res.remove(id);
        assert_eq!(removed, Some(info));
        assert!(res.get(id).is_none());
    }

    #[test]
    fn remove_nonexistent() {
        let res = Register::new();
        assert_eq!(res.remove(999), None);
    }

    #[test]
    fn find_existing_bgp_session_match() {
        let res = Register::new();
        let id = res.register();
        let info = IngressInfo::new()
            .with_remote_addr("10.0.0.1".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65000))
            .with_ingress_type(IngressType::Bgp);
        res.update_info(id, info.clone());

        let query = IngressInfo::new()
            .with_remote_addr("10.0.0.1".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65000))
            .with_ingress_type(IngressType::Bgp);

        let found = res.find_existing_bgp_session_and_claim(&query);
        let mut connected = info.with_state(IngressState::Connected);
        connected.history_generation = 1;
        connected.history_revision = 1;
        assert_eq!(found, Some((id, connected.clone())));
        assert_eq!(res.get(id), Some(connected));
        assert!(res.remove_if_disconnected(id).is_none());
    }

    #[test]
    fn find_existing_bgp_session_no_match_different_asn() {
        let res = Register::new();
        let id = res.register();
        let info = IngressInfo::new()
            .with_remote_addr("10.0.0.1".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65000))
            .with_ingress_type(IngressType::Bgp);
        res.update_info(id, info);

        let query = IngressInfo::new()
            .with_remote_addr("10.0.0.1".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65001))
            .with_ingress_type(IngressType::Bgp);

        assert_eq!(res.find_existing_bgp_session_and_claim(&query), None);
    }

    #[test]
    fn find_existing_bgp_session_no_match_different_type() {
        let res = Register::new();
        let id = res.register();
        let info = IngressInfo::new()
            .with_remote_addr("10.0.0.1".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65000))
            .with_ingress_type(IngressType::Bmp);
        res.update_info(id, info);

        let query = IngressInfo::new()
            .with_remote_addr("10.0.0.1".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65000))
            .with_ingress_type(IngressType::Bgp);

        assert_eq!(res.find_existing_bgp_session_and_claim(&query), None);
    }

    /// Mint a `BgpPath` child under `parent` in the given state.
    fn mk_path_child(
        res: &Register,
        parent: IngressId,
        path_id: u32,
        state: IngressState,
    ) -> IngressId {
        let id = res.register();
        res.update_info(
            id,
            IngressInfo::new()
                .with_ingress_type(IngressType::BgpPath)
                .with_parent_ingress(parent)
                .with_path_id(path_id)
                .with_state(state),
        );
        id
    }

    #[test]
    fn session_for_resolves_path_children_only() {
        let res = Register::new();
        let session = res.register();
        let child = mk_path_child(&res, session, 7, IngressState::Connected);

        // A BgpPath child resolves to its parent session.
        assert_eq!(res.session_for(child), session);
        // A session resolves to itself.
        assert_eq!(res.session_for(session), session);
        // An unknown id resolves to itself.
        assert_eq!(res.session_for(9999), 9999);
    }

    #[test]
    fn ids_for_parent_returns_path_children() {
        let res = Register::new();
        let session = res.register();
        let c1 = mk_path_child(&res, session, 1, IngressState::Connected);
        let c2 = mk_path_child(&res, session, 2, IngressState::Connected);
        // A child of some other parent must not appear.
        let other = res.register();
        mk_path_child(&res, other, 1, IngressState::Connected);

        let mut children = res.ids_for_parent(session);
        children.sort_unstable();
        let mut expected = vec![c1, c2];
        expected.sort_unstable();
        assert_eq!(children, expected);
    }

    #[test]
    fn non_mandatory_set_but_different() {
        let res = Register::new();
        let parent_id1 = res.register();
        let session_id1_a = res.register();

        let info1_a = IngressInfo::new()
            .with_parent_ingress(parent_id1)
            .with_remote_addr("1.2.3.4".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65000))
            .with_distinguisher([1, 2, 3, 4, 9, 9, 9, 9]);

        res.update_info(session_id1_a, info1_a.clone());

        let query1 = IngressInfo::new()
            .with_parent_ingress(parent_id1)
            .with_remote_addr("1.2.3.4".parse::<IpAddr>().unwrap())
            .with_remote_asn(Asn::from_u32(65000))
            .with_distinguisher([9, 9, 9, 9, 8, 8, 8, 8]);
        assert_eq!(res.find_existing_peer(&query1), None,);
    }
}
