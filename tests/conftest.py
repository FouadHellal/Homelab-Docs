import pytest

from tests.helpers import MemoryAudit


@pytest.fixture
def audit() -> MemoryAudit:
    return MemoryAudit()
