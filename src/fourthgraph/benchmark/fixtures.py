"""Registry shared by experiment discovery and complete-spend evaluation."""

from .byte_layout_fixture import ByteLayoutFixture
from .doubling_window_fixture import DoublingWindowFixture
from .formula_fixture import FIXTURES
from .hash_chain_fixture import HashChainFixture
from .point_add_fixture import PointAddFixture


CALL_SITE_FIXTURES = {fixture.name: fixture
                      for fixture in (PointAddFixture, HashChainFixture, ByteLayoutFixture, DoublingWindowFixture)}
SPEND_FIXTURES = (*FIXTURES, *CALL_SITE_FIXTURES)
