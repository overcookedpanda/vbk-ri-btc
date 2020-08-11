#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Copyright (c) 2019-2020 Xenios SEZC
# https://www.veriblock.org
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Test forking when shorted chain with endorsements win but contains invalid data.
"""

import struct
from typing import Optional
from test_framework.script import hash160, CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
from test_framework.util import hex_str_to_bytes
from test_framework.pop_const import KEYSTONE_INTERVAL, NETWORK_ID
from test_framework.pop import endorse_block, create_endorsed_chain, mine_vbk_blocks
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    connect_nodes,
    disconnect_nodes, assert_equal,
)

class PoPBadFr(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[], []]
        self.extra_args = [x + ['-debug=cmpctblock'] for x in self.extra_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_pypopminer()

    def setup_network(self):
        self.setup_nodes()

        for i in range(self.num_nodes - 1):
            connect_nodes(self.nodes[i + 1], i)
            self.sync_all()

    def get_best_block(self, node):
        hash = node.getbestblockhash()
        return node.getblock(hash)

    def get_vbk_best_block(self, node):
        hash = node.getvbkbestblockhash()
        return node.getvbkblock(hash)

    def endorse_block_bad(self, node, apm, vbkblock, height: int, addr: str, vtbs: Optional[int] = None) -> str:
        from pypopminer import PublicationData

        # get pubkey for that address
        pubkey = node.getaddressinfo(addr)['pubkey']
        pkh = hash160(hex_str_to_bytes(pubkey))
        script = CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])
        payoutInfo = script.hex()

        popdata = node.getpopdata(height)
        last_btc = popdata['last_known_bitcoin_blocks'][0]
        last_vbk = vbkblock
        header = popdata['block_header']
        pub = PublicationData()
        pub.header = header
        pub.payoutInfo = payoutInfo
        pub.identifier = NETWORK_ID

        if vtbs:
            apm.endorseVbkBlock(last_vbk, last_btc, vtbs)

        payloads = apm.endorseAltBlock(pub, last_vbk.getHash())
        payloads.atv.context.clear()
        payloads_list = payloads.prepare()
        payloads_list[0] = []
        node.submitpop(*payloads_list)
        return payloads.atv.getId()

    def _shorter_endorsed_chain_wins(self):
        self.log.warning("starting _shorter_endorsed_chain_wins()")

        # all nodes start with 50 blocks
        self.nodes[0].generate(nblocks=50)
        self.log.info("node0 mined 50 blocks")
        self.sync_blocks([self.nodes[0], self.nodes[1]], timeout=20)
        assert self.get_best_block(self.nodes[0])['height'] == 50
        assert self.get_best_block(self.nodes[1])['height'] == 50

        # node1 is disconnected 
        disconnect_nodes(self.nodes[1], 0)
        self.log.info("node1 is disconnected")

        # node0 mines 50 blocks, so total A height is 100
        self.nodes[0].generate(nblocks=50)

        self.log.info("generate 1 vbk block")
        vbk_blocks = mine_vbk_blocks(self.nodes[0], self.apm, 1)

        # mine a block on node[0] with this vbk block
        self.nodes[0].generate(nblocks=1)[0]

        # node1 mines another 20 blocks, so total B height is 70
        self.nodes[1].generate(nblocks=20)

        # fork A is at 101
        # fork B is at 70
        self.nodes[1].waitforblockheight(70)
        self.log.info("node1 mined 20 more blocks, total B height is 70")

        bestblocks = [self.get_best_block(x) for x in self.nodes]
        assert bestblocks[0] != bestblocks[1], "node[0,1] have same best hashes"

        bestvbkblocks = [self.get_vbk_best_block(x) for x in self.nodes]

        # endorse block 70 (fork B tip)
        addr1 = self.nodes[1].getnewaddress()

        containing_vbk_block = self.apm.vbkTip
        txid = self.endorse_block_bad(self.nodes[1], self.apm, containing_vbk_block, 70, addr1, 1)
        self.log.info("node1 endorsed block 70 (fork B tip)")
        # mine pop tx on node1
        containinghash = self.nodes[1].generate(nblocks=1)
        self.log.info("node1 mines 1 more block")

        connect_nodes(self.nodes[0], 1)
        self.log.info("node1 connected to node0")

        self.sync_blocks(self.nodes, timeout=30)
        self.log.info("nodes[0,1] are in sync")

        containingblock = self.nodes[0].getblock(containinghash[0])
        assert_equal(self.nodes[1].getblock(containinghash[0])['hash'], containingblock['hash'])
        tip = self.get_best_block(self.nodes[0])
        self.log.info("nodes[0,1] are in sync, pop tx containing block is {}".format(containingblock['height']))
        self.log.info("node0 tip is {}".format(tip['height']))

        # expected best block hash is fork A (has higher pop score)
        bestblocks = [self.get_best_block(x) for x in self.nodes]
        assert_equal(bestblocks[0]['hash'], bestblocks[1]['hash'])
        self.log.info("all nodes switched to common block")

        bestvbkblocks = [self.get_vbk_best_block(x) for x in self.nodes]

        for i in range(len(bestblocks)):
            assert bestblocks[i]['height'] == tip['height'], \
                "node[{}] expected to select shorter chain ({}) with higher pop score\n" \
                "but selected longer chain ({})".format(i, tip['height'], bestblocks[i]['height'])

        # get best headers view
        blockchaininfo = [x.getblockchaininfo() for x in self.nodes]
        for n in blockchaininfo:
            assert_equal(n['blocks'], n['headers'])

        self.log.info("all nodes selected fork B as best chain")
        self.log.warning("_shorter_endorsed_chain_wins() succeeded!")

    def run_test(self):
        """Main test logic"""

        self.sync_all(self.nodes)

        from pypopminer import MockMiner
        self.apm = MockMiner()

        self._shorter_endorsed_chain_wins()


if __name__ == '__main__':
    PoPBadFr().main()
