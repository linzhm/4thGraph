"""Convert between operator-entered USDC text and protocol base units."""
import re

from statement import uint

USDC_DECIMALS = 6
USDC_SCALE = 10**USDC_DECIMALS
# A uint64 number of base units has at most fourteen whole USDC digits.
_DECIMAL = re.compile(r"(0|[1-9][0-9]{0,13})(?:\.([0-9]{1,6}))?")


def parse_usdc(text: str) -> int:
    """Read an ASCII decimal amount without rounding or accepting other notations."""
    if type(text) is not str:
        raise ValueError("USDC amount must be a decimal string")
    match = _DECIMAL.fullmatch(text)
    if match is None:
        raise ValueError("expected a nonnegative USDC amount with at most six decimal places")
    whole, fraction = match.groups()
    quantity = int(whole) * USDC_SCALE + int((fraction or "").ljust(USDC_DECIMALS, "0"))
    uint(quantity, 8)
    return quantity


def format_usdc(quantity: int) -> str:
    """Render an exact protocol amount with six fractional digits."""
    uint(quantity, 8)
    whole, remainder = divmod(quantity, USDC_SCALE)
    return f"{whole}.{remainder:0{USDC_DECIMALS}d}"
