#!/usr/bin/env python3
# Copyright (c) 2014-2019 The Bitcoin Core developers
# Copyright (c) 2019-2020 Xenios SEZC
# https://www.veriblock.org
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Test with multiple nodes, and multiple PoP endorsements, checking to make sure nodes stay in sync.
"""
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    connect_nodes,
)
from test_framework.pop_const import NETWORK_ID

import time


class PopE2E(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [[], []]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_pypopminer()

    def setup_network(self):
        self.setup_nodes()

        for i in range(self.num_nodes - 1):
            connect_nodes(self.nodes[i + 1], i)
            self.sync_all()

    def _test_case(self):
        from pypopminer import PublicationData

        assert len(self.nodes[0].getpeerinfo()) == 1
        assert self.nodes[0].getpeerinfo()[0]['banscore'] == 0
        assert len(self.nodes[1].getpeerinfo()) == 1
        assert self.nodes[1].getpeerinfo()[0]['banscore'] == 0

        vbk_blocks_amount = 3000
        self.log.info("generate vbk blocks on node0, amount {}".format(vbk_blocks_amount))
        vbk_blocks = []
        for i in range(vbk_blocks_amount):
            vbk_blocks.append(self.apm.mineVbkBlocks(1))

        assert len(vbk_blocks) == vbk_blocks_amount

        vtbs_amount = 1000
        self.log.info("generate vtbs on node0, amount {}".format(vtbs_amount))
        for i in range(vtbs_amount):
            self.apm.endorseVbkBlock(self.apm.vbkTip, self.apm.btcTip.getHash(), 1)

        self.nodes[0].generate(nblocks=10)

        self.log.info("endorse 5 alt block")    
        p = PublicationData()
        p.identifier = NETWORK_ID
        p.header = self.nodes[0].getpopdata(5)['block_header']
        p.payoutInfo = "0014aaddff"

        pop_data = self.apm.endorseAltBlock(p, vbk_blocks[0].getHash())
        assert len(pop_data.vtbs) == vtbs_amount

        vtbs = [x.toVbkEncodingHex() for x in pop_data.vtbs]
        self.nodes[0].submitpop([b.toVbkEncodingHex() for b in vbk_blocks], vtbs, [pop_data.atv.toVbkEncodingHex()])

        assert len(self.nodes[0].getpeerinfo()) == 1
        assert self.nodes[0].getpeerinfo()[0]['banscore'] == 0
        assert len(self.nodes[1].getpeerinfo()) == 1
        assert self.nodes[1].getpeerinfo()[0]['banscore'] == 0

        containingblock = self.nodes[0].generate(nblocks=1)
        containingblock = self.nodes[0].getblock(containingblock[0])

        assert len(containingblock['pop']['data']['vtbs']) == vtbs_amount
        assert len(containingblock['pop']['data']['vbkblocks']) == vbk_blocks_amount + vtbs_amount + 1

        self.log.info("endorse 6 alt block")
        p = PublicationData()
        p.identifier = NETWORK_ID
        p.header = self.nodes[0].getpopdata(6)['block_header']
        p.payoutInfo = "0014aaddff"

        pop_data = self.apm.endorseAltBlock(p, vbk_blocks[0].getHash())
        assert len(pop_data.vtbs) == vtbs_amount

        vtbs = [x.toVbkEncodingHex() for x in pop_data.vtbs]
        self.nodes[0].submitpop([b.toVbkEncodingHex() for b in vbk_blocks], vtbs, [pop_data.atv.toVbkEncodingHex()])

        assert len(self.nodes[0].getpeerinfo()) == 1
        assert self.nodes[0].getpeerinfo()[0]['banscore'] == 0
        assert len(self.nodes[1].getpeerinfo()) == 1
        assert self.nodes[1].getpeerinfo()[0]['banscore'] == 0

        containingblock = self.nodes[0].generate(nblocks=1)
        containingblock = self.nodes[0].getblock(containingblock[0])
        time.sleep(5)

        self.log.info("sync all nodes")
        self.sync_all(self.nodes)

        assert len(self.nodes[0].getpeerinfo()) == 1
        assert self.nodes[0].getpeerinfo()[0]['banscore'] == 0
        assert len(self.nodes[1].getpeerinfo()) == 1
        assert self.nodes[1].getpeerinfo()[0]['banscore'] == 0

    def run_test(self):
        """Main test logic"""

        self.sync_all(self.nodes)

        from pypopminer import MockMiner

        self.apm = MockMiner()

        self._test_case()
       
if __name__ == '__main__':
    PopE2E().main()
