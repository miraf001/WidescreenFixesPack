"""Selected virtual-pad exercise; no attack, interaction, or menu buttons."""
from dataclasses import dataclass
import math

CONTROL_MESSAGE = 0x8000 + 0x52
CMD_STATUS, CMD_START, CMD_STOP, CMD_RELEASE, CMD_QUIT, CMD_GAME_PID = range(1, 7)
CMD_PAD = 7


@dataclass(frozen=True)
class DemoInput:
    lx: float = 0.0
    ly: float = 0.0
    rx: float = 0.0
    ry: float = 0.0
    lt: int = 0


def demo_input(elapsed: float, duration: float) -> DemoInput:
    """Twelve-second balanced stick sequence, with neutral pauses.

    Input vectors balance; actual world position is not guaranteed to return
    exactly because the game has collision and camera-relative movement.
    """
    if not math.isfinite(elapsed) or not 0 <= elapsed < duration:
        return DemoInput()
    t = elapsed % 12.0
    if t < 1.8:
        return DemoInput(ly=0.55)
    if 2.2 <= t < 4.0:
        return DemoInput(ly=-0.55)
    if 4.4 <= t < 5.8:
        return DemoInput(rx=0.32, lt=255)
    if 5.8 <= t < 7.2:
        return DemoInput(rx=-0.32, lt=255)
    if 7.6 <= t < 8.6:
        return DemoInput(lx=-0.55)
    if 8.6 <= t < 9.6:
        return DemoInput(lx=0.55)
    if 10.0 <= t < 10.6:
        return DemoInput(ry=0.25, lt=255)
    if 10.6 <= t < 11.2:
        return DemoInput(ry=-0.25, lt=255)
    return DemoInput()
