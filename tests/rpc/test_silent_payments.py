import test_sp_roundtrip

from . import *


@pytest.mark.mnemonic(mnemonics.singlesig)
def test_silent_payment_roundtrip(jade, mnemonic):
    """Pay Jade's own silent payment address, then scan for the payment.

    Checks the descriptor export and signing against each other, and the
    BIP352 output against an implementation that is not the one Jade uses.
    Skipped unless the vendored libwally has been built for the host.
    """
    if not test_sp_roundtrip.load_wally():
        pytest.skip('No libwally host build')
    test_sp_roundtrip.run_roundtrip(jade, 'localtest', verbose=False)
