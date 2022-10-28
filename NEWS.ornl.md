ORNL Libfabric release notes
=============================

This file contains the main features as well as overviews of specific
bug fixes (and other actions) for each version of ORNL Libfabric.

v1.16.x.srx.ornl.10282022, Fri Oct 10, 2022
============================================

## CORE
- Add address matching call back to peer_srx infrastructure
- Add support for ROCR IPC
- Support ROCR asynchronous memory copies
- Add support for XPMEM

## SHM
- Use the XPMEM infrastructure for shared memory transfer
- Add FI_USE_XPMEM environment variable to select XPMEM
- Support H2D through XPMEM
- Use the ROCR IPC infrastructure

## LINKx
- Initial implementation
- Support shared completion queues
- Support shared receive queues

## CXI
- Port latest drop from April 2022 and rebase on v1.16.x
- Support shared completion queues
- Support shared receive queues

## Performance Notes
- osu_bw and osu_bibw performance is comparable between CrayMPICH implementation
  and this implementation
- osu_all2all cxi performance with 71 nodes 1 process per node is comparable between
  CrayMPICH implementation and this implementation
- osu_all2all shm test with 8 processes per node and 1 node shows significant
  performance differential between CrayMPICH and the SHM provider. The SHM provider
  significantly under performs.
- Tests results are recorded here: https://confluence.ccs.ornl.gov/x/1gYiEg

