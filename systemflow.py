
"""
user: manual sent pk to uni
uni: create tx after user grad
uni: sign tx with private key
uni: send tx to network

nw: receive tx (on_transaction_received)
nw: verify tx signature (on_transaction_received)
nw: broadcast tx to network (gossip tx)

validator: receive tx and store in mempool (pending)

proposer: check if it's their turn (round-robin or rule)
proposer: collect txs from mempool
proposer: create block
proposer: sign block with private key
proposer: broadcast block to validator set

validator: receive proposed block
validator: verify block signature and contents
validator: create vote
validator: sign vote with private key
validator: sent vote to proposer
proposer: collect votes
proposer: if vote threshold reached → commit block
proposer: broadcast committed block

user: receive cert or confirmation (off-chain or on-chain response)
"""