use std::collections::BTreeMap;

use anyhow::{ensure, Result};
use filecoin_proofs_v1::with_shape;

use crate::types::VanillaProofBytes;
use crate::{
    ChallengeSeed, FallbackPoStSectorProof, MerkleTreeTrait, PartitionSnarkProof, PoStType,
    PrivateReplicaInfo, ProverId, PublicReplicaInfo, RegisteredPoStProof, SectorId, SnarkProof,
    AggregateSnarkProof, RegisteredAggregationProof,
};

pub fn generate_winning_post_sector_challenge(
    proof_type: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    sector_set_len: u64,
    prover_id: ProverId,
) -> Result<Vec<u64>> {
    ensure!(
        proof_type.typ() == PoStType::Winning,
        "invalid post type provided"
    );

    with_shape!(
        u64::from(proof_type.sector_size()),
        generate_winning_post_sector_challenge_inner,
        proof_type,
        randomness,
        sector_set_len,
        prover_id,
    )
}

fn generate_winning_post_sector_challenge_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof_v1: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    sector_set_len: u64,
    prover_id: ProverId,
) -> Result<Vec<u64>> {
    filecoin_proofs_v1::generate_winning_post_sector_challenge::<Tree>(
        &registered_proof_v1.as_v1_config(),
        randomness,
        sector_set_len,
        prover_id,
    )
}

pub fn generate_fallback_sector_challenges(
    registered_post_proof_type: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    pub_sectors: &[SectorId],
    prover_id: ProverId,
) -> Result<BTreeMap<SectorId, Vec<u64>>> {
    ensure!(!pub_sectors.is_empty(), "no sectors supplied");

    with_shape!(
        u64::from(registered_post_proof_type.sector_size()),
        generate_fallback_sector_challenges_inner,
        registered_post_proof_type,
        randomness,
        pub_sectors,
        prover_id,
    )
}

fn generate_fallback_sector_challenges_inner<Tree: 'static + MerkleTreeTrait>(
    registered_post_proof_type: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    pub_sectors: &[SectorId],
    prover_id: ProverId,
) -> Result<BTreeMap<SectorId, Vec<u64>>> {
    filecoin_proofs_v1::generate_fallback_sector_challenges::<Tree>(
        &registered_post_proof_type.as_v1_config(),
        randomness,
        pub_sectors,
        prover_id,
    )
}

pub fn generate_single_vanilla_proof(
    registered_post_proof_type: RegisteredPoStProof,
    sector_id: SectorId,
    replica: &PrivateReplicaInfo,
    challenges: &[u64],
) -> Result<VanillaProofBytes> {
    ensure!(!challenges.is_empty(), "no challenges supplied");

    with_shape!(
        u64::from(registered_post_proof_type.sector_size()),
        generate_single_vanilla_proof_inner,
        registered_post_proof_type,
        sector_id,
        replica,
        challenges,
    )
}

fn generate_single_vanilla_proof_inner<Tree: 'static + MerkleTreeTrait>(
    registered_post_proof_type: RegisteredPoStProof,
    sector_id: SectorId,
    replica: &PrivateReplicaInfo,
    challenges: &[u64],
) -> Result<VanillaProofBytes> {
    let PrivateReplicaInfo {
        registered_proof,
        comm_r,
        cache_dir,
        replica_path,
    } = replica;

    ensure!(
        registered_proof == &registered_post_proof_type,
        "can only generate the same kind of PoSt"
    );

    let info_v1 = filecoin_proofs_v1::PrivateReplicaInfo::<Tree>::new(
        replica_path.clone(),
        *comm_r,
        cache_dir.into(),
    )?;

    let vanilla_proof: FallbackPoStSectorProof<Tree> =
        filecoin_proofs_v1::generate_single_vanilla_proof::<Tree>(
            &registered_post_proof_type.as_v1_config(),
            sector_id,
            &info_v1,
            challenges,
        )?;

    let vanilla_proof_bytes_v1: VanillaProofBytes = bincode::serialize(&vanilla_proof)?;

    Ok(vanilla_proof_bytes_v1)
}

pub fn generate_winning_post_with_vanilla(
    registered_post_proof_type: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: &[VanillaProofBytes],
) -> Result<Vec<(RegisteredPoStProof, SnarkProof)>> {
    with_shape!(
        u64::from(registered_post_proof_type.sector_size()),
        generate_winning_post_with_vanilla_inner,
        registered_post_proof_type,
        randomness,
        prover_id,
        vanilla_proofs,
    )
}

fn generate_winning_post_with_vanilla_inner<Tree: 'static + MerkleTreeTrait>(
    registered_post_proof_type: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: &[VanillaProofBytes],
) -> Result<Vec<(RegisteredPoStProof, SnarkProof)>> {
    ensure!(
        !vanilla_proofs.is_empty(),
        "vanilla_proofs cannot be an empty list"
    );

    let fallback_post_sector_proofs: Vec<FallbackPoStSectorProof<Tree>> = vanilla_proofs
        .iter()
        .map(|proof_bytes| {
            let proof: FallbackPoStSectorProof<Tree> = bincode::deserialize(proof_bytes)?;
            Ok(proof)
        })
        .collect::<Result<_>>()?;

    let posts_v1 = filecoin_proofs_v1::generate_winning_post_with_vanilla::<Tree>(
        &registered_post_proof_type.as_v1_config(),
        randomness,
        prover_id,
        fallback_post_sector_proofs,
    )?;

    // once there are multiple versions, merge them before returning

    Ok(vec![(registered_post_proof_type, posts_v1)])
}

pub fn generate_winning_post(
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<Vec<(RegisteredPoStProof, SnarkProof)>> {
    ensure!(!replicas.is_empty(), "no replicas supplied");
    let registered_post_proof_type_v1 = replicas
        .values()
        .next()
        .map(|v| v.registered_proof)
        .expect("replica map failure");
    ensure!(
        registered_post_proof_type_v1.typ() == PoStType::Winning,
        "invalid post type provided"
    );

    with_shape!(
        u64::from(registered_post_proof_type_v1.sector_size()),
        generate_winning_post_inner,
        registered_post_proof_type_v1,
        randomness,
        replicas,
        prover_id,
    )
}

fn generate_winning_post_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof_v1: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<Vec<(RegisteredPoStProof, SnarkProof)>> {
    let mut replicas_v1 = Vec::new();

    for (id, info) in replicas.iter() {
        let PrivateReplicaInfo {
            registered_proof,
            comm_r,
            cache_dir,
            replica_path,
        } = info;

        ensure!(
            registered_proof == &registered_proof_v1,
            "can only generate the same kind of PoSt"
        );
        let info_v1 = filecoin_proofs_v1::PrivateReplicaInfo::new(
            replica_path.clone(),
            *comm_r,
            cache_dir.into(),
        )?;

        replicas_v1.push((*id, info_v1));
    }

    ensure!(!replicas_v1.is_empty(), "missing v1 replicas");
    let posts_v1 = filecoin_proofs_v1::generate_winning_post::<Tree>(
        &registered_proof_v1.as_v1_config(),
        randomness,
        &replicas_v1,
        prover_id,
    )?;

    // once there are multiple versions, merge them before returning

    Ok(vec![(registered_proof_v1, posts_v1)])
}

pub fn verify_winning_post(
    randomness: &ChallengeSeed,
    proof: &[u8],
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
) -> Result<bool> {
    ensure!(!replicas.is_empty(), "no replicas supplied");
    let registered_post_proof_type_v1 = replicas
        .values()
        .next()
        .map(|v| v.registered_proof)
        .expect("replica map failure");
    ensure!(
        registered_post_proof_type_v1.typ() == PoStType::Winning,
        "invalid post type provided"
    );

    with_shape!(
        u64::from(registered_post_proof_type_v1.sector_size()),
        verify_winning_post_inner,
        registered_post_proof_type_v1,
        randomness,
        proof,
        replicas,
        prover_id,
    )
}

fn verify_winning_post_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof_v1: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    proof: &[u8],
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
) -> Result<bool> {
    let mut replicas_v1 = Vec::new();

    for (id, info) in replicas.iter() {
        let PublicReplicaInfo {
            registered_proof,
            comm_r,
        } = info;

        ensure!(
            registered_proof == &registered_proof_v1,
            "can only generate the same kind of PoSt"
        );

        let info_v1 = filecoin_proofs_v1::PublicReplicaInfo::new(*comm_r)?;
        replicas_v1.push((*id, info_v1));
    }

    let valid_v1 = filecoin_proofs_v1::verify_winning_post::<Tree>(
        &registered_proof_v1.as_v1_config(),
        randomness,
        &replicas_v1,
        prover_id,
        proof,
    )?;

    // once there are multiple versions, merge them before returning

    Ok(valid_v1)
}

pub fn generate_window_post_with_vanilla(
    registered_post_proof_type: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: &[VanillaProofBytes],
) -> Result<(RegisteredPoStProof, SnarkProof)> {
    with_shape!(
        u64::from(registered_post_proof_type.sector_size()),
        generate_window_post_with_vanilla_inner,
        registered_post_proof_type,
        randomness,
        prover_id,
        vanilla_proofs,
    )
}

fn generate_window_post_with_vanilla_inner<Tree: 'static + MerkleTreeTrait>(
    registered_post_proof_type: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: &[VanillaProofBytes],
) -> Result<(RegisteredPoStProof, SnarkProof)> {
    ensure!(
        !vanilla_proofs.is_empty(),
        "vanilla_proofs cannot be an empty list"
    );

    let fallback_post_sector_proofs: Vec<FallbackPoStSectorProof<Tree>> = vanilla_proofs
        .iter()
        .map(|proof_bytes| {
            let proof: FallbackPoStSectorProof<Tree> = bincode::deserialize(proof_bytes)?;
            Ok(proof)
        })
        .collect::<Result<_>>()?;

    let posts_v1 = filecoin_proofs_v1::generate_window_post_with_vanilla::<Tree>(
        &registered_post_proof_type.as_v1_config(),
        randomness,
        prover_id,
        fallback_post_sector_proofs,
    )?;

    // once there are multiple versions, merge them before returning

    Ok((registered_post_proof_type, posts_v1))
}

pub fn generate_window_post(
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<(RegisteredPoStProof, SnarkProof)> {
    ensure!(!replicas.is_empty(), "no replicas supplied");
    let registered_post_proof_type_v1 = replicas
        .values()
        .next()
        .map(|v| v.registered_proof)
        .expect("replica map failure");
    ensure!(
        registered_post_proof_type_v1.typ() == PoStType::Window,
        "invalid post type provided"
    );

    with_shape!(
        u64::from(registered_post_proof_type_v1.sector_size()),
        generate_window_post_inner,
        registered_post_proof_type_v1,
        randomness,
        replicas,
        prover_id,
    )
}

fn generate_window_post_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof_v1: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<(RegisteredPoStProof, SnarkProof)> {
    let mut replicas_v1 = BTreeMap::new();

    for (id, info) in replicas.iter() {
        let PrivateReplicaInfo {
            registered_proof,
            comm_r,
            cache_dir,
            replica_path,
        } = info;

        ensure!(
            registered_proof == &registered_proof_v1,
            "can only generate the same kind of PoSt"
        );
        let info_v1 = filecoin_proofs_v1::PrivateReplicaInfo::new(
            replica_path.clone(),
            *comm_r,
            cache_dir.into(),
        )?;

        replicas_v1.insert(*id, info_v1);
    }

    ensure!(!replicas_v1.is_empty(), "missing v1 replicas");
    let posts_v1 = filecoin_proofs_v1::generate_window_post::<Tree>(
        &registered_proof_v1.as_v1_config(),
        randomness,
        &replicas_v1,
        prover_id,
    )?;

    // once there are multiple versions, merge them before returning

    Ok((registered_proof_v1, posts_v1))
}

pub fn verify_window_post(
    randomness: &ChallengeSeed,
    proof: &(RegisteredPoStProof, &[u8]),
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
) -> Result<bool> {
    ensure!(!replicas.is_empty(), "no replicas supplied");

    let registered_post_proof_type_v1 = proof.0;

    ensure!(
        registered_post_proof_type_v1.typ() == PoStType::Window,
        "invalid post type provided"
    );
    ensure!(
        registered_post_proof_type_v1.major_version() == 1,
        "only V1 supported"
    );

    with_shape!(
        u64::from(registered_post_proof_type_v1.sector_size()),
        verify_window_post_inner,
        registered_post_proof_type_v1,
        randomness,
        proof,
        replicas,
        prover_id,
    )
}

fn verify_window_post_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof_v1: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    proof: &(RegisteredPoStProof, &[u8]),
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
) -> Result<bool> {
    let mut replicas_v1 = BTreeMap::new();

    for (id, info) in replicas.iter() {
        let PublicReplicaInfo {
            registered_proof,
            comm_r,
        } = info;

        ensure!(
            registered_proof == &registered_proof_v1,
            "can only generate the same kind of PoSt"
        );

        let info_v1 = filecoin_proofs_v1::PublicReplicaInfo::new(*comm_r)?;
        replicas_v1.insert(*id, info_v1);
    }

    let valid_v1 = filecoin_proofs_v1::verify_window_post::<Tree>(
        &registered_proof_v1.as_v1_config(),
        randomness,
        &replicas_v1,
        prover_id,
        proof.1,
    )?;

    // once there are multiple versions, merge them before returning

    Ok(valid_v1)
}

pub fn aggregate_window_post_proofs(
    registered_aggregation: RegisteredAggregationProof,
    randomnesses: &[ChallengeSeed],
    proofs: &[(RegisteredPoStProof, &[u8])], 
    total_sector_count: usize,
) -> Result<AggregateSnarkProof> {
    ensure!(
        randomnesses.len() == proofs.len(),
        "the lenth of randomness and proof is not match"
    );

    let registered_post_proof_type_v1 = proofs[0].0;
    ensure!(
        registered_post_proof_type_v1.typ() == PoStType::Window,
        "invalid post type provided"
    );

    ensure!(
        registered_aggregation == RegisteredAggregationProof::SnarkPackV1,
        "unusupported aggregation version"
    );

    with_shape!(
        u64::from(registered_post_proof_type_v1.sector_size()),
        aggregate_window_post_proofs_inner,
        registered_post_proof_type_v1,
        randomnesses,
        proofs,
        total_sector_count,
    )
}

fn aggregate_window_post_proofs_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof_v1: RegisteredPoStProof,
    randomnesses: &[ChallengeSeed],
    proofs: &[(RegisteredPoStProof, &[u8])],
    total_sector_count: usize,
) -> Result<AggregateSnarkProof> {
    let mut agg_proofs: Vec<Vec<u8>> = Vec::new();

    for (registered_proof, proof) in proofs.into_iter() {

        ensure!(
            registered_proof == &registered_proof_v1,
            "can only aggregate the same kind of PoSt"
        );
        agg_proofs.push(proof.to_vec());
    }

    ensure!(!agg_proofs.is_empty(), "missing proofs");
    filecoin_proofs_v1::aggregate_window_post_proofs::<Tree>(
        &registered_proof_v1.as_v1_config(),
        randomnesses,
        agg_proofs.as_slice(),
        total_sector_count,
    )
}

pub fn verify_aggregate_window_post_proofs(
    registered_proof_v1: RegisteredPoStProof,
    registered_aggregation: RegisteredAggregationProof,
    prover_id: ProverId,
    aggregate_proof_bytes: AggregateSnarkProof,
    randomnesses: &[ChallengeSeed],
    replicas: &[BTreeMap<SectorId, PublicReplicaInfo>],
) -> Result<bool> {
    ensure!(!replicas.is_empty(), "no replicas supplied");
    ensure!(
        randomnesses.len() == replicas.len(),
        "Randomnesses and Replica don't match"
    );

    ensure!(
        registered_proof_v1.major_version() == 1,
        "only V1 supported"
    );

    ensure!(
        registered_aggregation == RegisteredAggregationProof::SnarkPackV1,
        "unusupported aggregation version"
    );

    with_shape!(
        u64::from(registered_proof_v1.sector_size()),
        verify_aggregate_window_post_proofs_inner,
        registered_proof_v1,
        prover_id,
        aggregate_proof_bytes,
        randomnesses,
        replicas,
    )
}

fn verify_aggregate_window_post_proofs_inner<Tree: 'static + MerkleTreeTrait>(
    registered_proof_v1: RegisteredPoStProof,
    prover_id: ProverId,
    aggregate_proof_bytes: AggregateSnarkProof,
    randomnesses: &[ChallengeSeed],
    replicas: &[BTreeMap<SectorId, PublicReplicaInfo>],
) -> Result<bool> {
    let mut replica_infos_v1 = Vec::new();

    for replica in replicas.iter() {
        let mut replica_info_v1 = BTreeMap::new();
        for (id, info) in replica.iter(){
            let PublicReplicaInfo {
                registered_proof,
                comm_r,
            } = info;

            ensure!(
                registered_proof == &registered_proof_v1,
                "can only verify the same kind of PoSt"
            );

            let info_v1 = filecoin_proofs_v1::PublicReplicaInfo::new(*comm_r)?;
            replica_info_v1.insert(*id, info_v1);
        }
        replica_infos_v1.push(replica_info_v1);
    }

    let valid_v1 = filecoin_proofs_v1::verify_aggregate_window_post_proofs::<Tree>(
        &registered_proof_v1.as_v1_config(),
        prover_id,
        aggregate_proof_bytes,
        randomnesses,
        replica_infos_v1.as_slice(),
    )?;

    // once there are multiple versions, merge them before returning

    Ok(valid_v1)
}

pub fn get_num_partition_for_fallback_post(
    registered_post_proof_v1: RegisteredPoStProof,
    num_sectors: usize,
) -> Result<usize> {
    ensure!(
        registered_post_proof_v1.typ() == PoStType::Window,
        "invalid post type provided"
    );
    ensure!(
        registered_post_proof_v1.major_version() == 1,
        "only V1 supported"
    );

    Ok(filecoin_proofs_v1::get_num_partition_for_fallback_post(
        &registered_post_proof_v1.as_v1_config(),
        num_sectors,
    ))
}

pub fn merge_window_post_partition_proofs(
    registered_post_proof_v1: RegisteredPoStProof,
    proofs: Vec<PartitionSnarkProof>,
) -> Result<SnarkProof> {
    ensure!(
        registered_post_proof_v1.typ() == PoStType::Window,
        "invalid post type provided"
    );
    ensure!(
        registered_post_proof_v1.major_version() == 1,
        "only V1 supported"
    );

    filecoin_proofs_v1::merge_window_post_partition_proofs(proofs)
}

fn generate_single_window_post_with_vanilla_inner<Tree: 'static + MerkleTreeTrait>(
    registered_post_proof_v1: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: &[VanillaProofBytes],
    partition_index: usize,
) -> Result<PartitionSnarkProof> {
    let fallback_post_sector_proofs: Vec<FallbackPoStSectorProof<Tree>> = vanilla_proofs
        .iter()
        .map(|proof_bytes| {
            let proof: FallbackPoStSectorProof<Tree> = bincode::deserialize(proof_bytes)?;
            Ok(proof)
        })
        .collect::<Result<_>>()?;

    filecoin_proofs_v1::generate_single_window_post_with_vanilla(
        &registered_post_proof_v1.as_v1_config(),
        randomness,
        prover_id,
        fallback_post_sector_proofs,
        partition_index,
    )
}

pub fn generate_single_window_post_with_vanilla(
    registered_post_proof_v1: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: &[VanillaProofBytes],
    partition_index: usize,
) -> Result<PartitionSnarkProof> {
    ensure!(
        registered_post_proof_v1.typ() == PoStType::Window,
        "invalid post type provided"
    );
    ensure!(
        registered_post_proof_v1.major_version() == 1,
        "only V1 supported"
    );

    with_shape!(
        u64::from(registered_post_proof_v1.sector_size()),
        generate_single_window_post_with_vanilla_inner,
        registered_post_proof_v1,
        randomness,
        prover_id,
        vanilla_proofs,
        partition_index,
    )
}
