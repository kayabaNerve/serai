# Economics

The economics of the Serai codebase are delineated into two different epochs of
time.

1) Pre-economic security.

   Any validator set has yet to achieve economic security.

2) Post-economic security.

    All validator sets have achieved economic security.

These two epochs have vastly different considerations and accordingly each have
their own set of rules.

## Genesis

At genesis, a set of genesis nodes (presumably community leaders sufficiently
trusted) will start the network. They will perform a DKG and publish the initial
addresses for Serai (over Bitcoin, Ethereum, and Monero) to receive coins with
(BTC, ETH, DAI, and XMR, further referred to with indifference as XYZ).

```
GENESIS_SRI = 100,000,000.000000 SRI
GENESIS_LIQUIDITY_TIME = 30 days
```

Over `GENESIS_LIQUIDITY_TIME`, any user will be able to provide XYZ. At the end
of `GENESIS_LIQUIDITY_TIME`, the validators will oraclize the price of 1 XYZ
in terms of 0.00000001 BTC (except for BTC). With the value of `sriXYZ`
considered equivalent to the value of `XYZ`, the value of each pool is
determined. `GENESIS_SRI` is proportionately distributed.

Genesis is now complete. Swaps become available.

## Pre-economic Security

### Liquidity Providers

Due to Serai's pools operating with an `xyk` formula, for `M XYZ : N SRI`, the
only way for the XYZ portion to decrease is for SRI exogenous to the pool to
be introduced. If SRI is swapped out from the pools, and swapped back in, it
has a neutral effect (slightly in favor to the pool due to fees) and accordingly
isn't considered exogenous.

Exogenous SRI has four possible sources:

1) Circulating SRI.

    There will be no distributions of SRI during this era which isn't
    `GENESIS_SRI` or staked.

2) Removed liquidity.

    All liquidity removed during this era will only yield the XYZ component,
    burning the SRI.

3) Removed stake.

    Due to the lack of unused capacity in the economic security, there is an
    inability to unstake SRI. If any individual network has achieved unused
    capacity, unstaking still is not allowed so long as any network has yet to.

4) Intra-pool SRI movement.

    For coins XYZ, ABC, the XYZ pool may `+XYZ, -SRI`. This enables `+SRI, -ABC`
    in the ABC pool. To resolve this, each pool tracks `+XYZ` and `+SRI`
    received from such swaps. When an XYZ liquidity provider removes their
    liquidity, they do not receive the XYZ in question. When an ABC liquidity
    provider removes their liquidity, they do receive the SRI in question. This
    enables them to swap it to the XYZ and recoup their value, barring fees
    and ABC-XYZ price fluctuations.

Accordingly, exogenous is considered managed, with the intention being for the
XYZ quantity received to be greater than or equal to the initial contribution.

### Swap to Staked SRI

At the median price, any external actor may swap XYZ to SRI outside of the
pools. This SRI would be freshly minted and immediately staked to a validator
within a set for an external network. The XYZ received would be used to form
protocol-owned liquidity, making all existing LPs have more XYZ and less SRI.

### Emissions

Emissions only start after genesis.

```
INITIAL_PERIOD = 60 days
INITIAL_REWARD = 100,000 SRI / BLOCKS_PER_DAY
LITERAL_STAKE_REQUIRED = 1.5 * sri_in_pools()
EXTERNAL_STAKE_REQUIRED = LITERAL_STAKE_REQUIRED * 1.2
SERAI_VALIDATORS_DESIRED_PERCENTAGE = 0.2
STAKE_REQUIRED = EXTERNAL_STAKE_REQUIRED / (1 - SERAI_VALIDATORS_DESIRED_PERCENTAGE)
SERAI_VALIDATORS_STAKE_DESIRED = SERAI_VALIDATORS_DESIRED_PERCENTAGE * STAKE_REQUIRED
SECURE_BY = 1 year
```

`CURRENT_STAKE` is the amount of stake from each external network, capped at the
amount needed for each external network to be secure (so a validator set with
unused capacity only counts for the amount required to be secure).

The block reward from genesis till the end of `INITIAL_PERIOD` is fixed to
`INITIAL_REWARD`. Afterwards, the block reward is
`(STAKE_REQUIRED - CURRENT_STAKE) / blocks_until(SECURE_BY)`.

This ensures economic security by the specified date. As economic security by
printing SRI is undesirable, the amount of economic security so achieved is a
function of necessity due to lack of interest in staking.

Emissions are distributed to each validator set as a function of their distance
from economic security. For the Serai validator set, which does not have a
literal evaluation of this, `SERAI_VALIDATORS_STAKE_DESIRED` is used.

### Fees

The fees for a swap within a pool are 0.6%. While aggressive compared to
comparables and centralized exchanges, this is argued as better than instant
exchangers while the protocol near-exclusively offers specific functionality.
This is a prime opportunity for the protocol to capitalize on.

These fees are then used to form protocol-owned liquidity.

## Post-economic Security

### Liquidity Providers

```
GENESIS_SRI_TRICKLE_FEED = 180 days
```

Liquidity may be added as the capacity allows. Genesis liquidity may be removed
without burning the SRI portion in its entirety, instead burning
`(GENESIS_SRI_TRICKLE_FEED - days_since_security()) / GENESIS_SRI_TRICKLE_FEED`
of the amount.

### Emissions

```
BLOCK_REWARD = 20,000,000 SRI / BLOCKS_PER_YEAR
```

`BLOCK_REWARD * SERAI_VALIDATORS_DESIRED_PERCENTAGE` is distributed to the Serai
validator set.

External networks have their proportions decided equivalently to the proportions
of their fees. Once the network's proportion is decided, a proportion between
the pool and the validators is decided.

```
DESIRED_UNUSED_CAPACITY = 0.1
ACCURACY_MULTIPLIER = 10000
DISTRIBUTION = (capacity_of_network() * ACCURACY_MULTIPLIER) / unused_capacity()
DESIRED_DISTRIBUTION = DESIRED_UNUSED_CAPACITY * ACCURACY_MULTIPLIER
```

`DESIRED_DISTRIBUTION : DISTRIBUTION` is the ratio used to distribute to the
pool and validators, respectively. If unused capacity ever hits 0,
`DISTRIBUTION = inf`, so all of the emissions will go to the validators for that
network.

### Fees

The amount of fees charged remains the same. The fees are taken in SRI. Half
remains in the pool, effectively being distributed to LPs, with the rest burnt.

The intention here is to further reward all parties as usage increases. While
burning SRI presumably increases the value of all remaining SRI, this may be
arbitraged away as the LPs suffer impermanent loss. LPs also represent a
minority of the network's SRI, so they're not the primary benefactor to such a
scheme. This is why the explicit distribution exists.

Validators are presumed to represent a majority of the network's SRI, and are
entirely denominated in SRI, hence why burning SRI alone is considered
sufficient for them.

## Social Policy

Serai, as a social system, can be argued to have expectations despite the lack
of any requirements. Regarding the economics, the expectation should be a degree
of change.

As the network grows in volume, or loses users due to the fees, the fees should
be adjusted. As the network non-sustainably incentivizes, or fails to properly
incentivize, the block reward should be adjusted. How fees are distributed
should also be considered, as there is an argument to entirely burn them.

There is also the potential in the future to grow the SRI supply as new
integrations occur. This is left unexplored at this time.
