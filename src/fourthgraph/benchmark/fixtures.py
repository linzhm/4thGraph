"""Registry shared by experiment discovery and complete-spend evaluation."""

from .formula_fixture import FIXTURES
from .hash_chain_fixture import HashChainFixture
from .point_add_fixture import PointAddFixture


CALL_SITE_FIXTURES = {fixture.name: fixture for fixture in (PointAddFixture, HashChainFixture)}
SPEND_FIXTURES = (*FIXTURES, *CALL_SITE_FIXTURES)
