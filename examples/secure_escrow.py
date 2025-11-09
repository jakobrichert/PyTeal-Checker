"""
Example: Secure Hash Time Locked Contract (HTLC)
Demonstrates proper security validations in PyTeal
"""

from pyteal import *


def htlc_escrow(
    tmpl_seller=Addr("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"),
    tmpl_buyer=Addr("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"),
    tmpl_fee=Int(1000),
    tmpl_secret=Bytes("base32", "2323232323232323"),
    tmpl_hash_fn=Sha256,
    tmpl_timeout=Int(3000),
):
    """
    Secure HTLC implementation with all necessary validations
    """

    # SECURE: Fee validation prevents excessive fees
    fee_cond = Txn.fee() <= tmpl_fee

    # SECURE: Comprehensive safety checks
    safety_cond = And(
        Txn.type_enum() == TxnType.Payment,
        # SECURE: Prevents account takeover via rekey
        Txn.rekey_to() == Global.zero_address(),
        # SECURE: Prevents fund drainage via close_remainder
        Txn.close_remainder_to() == Global.zero_address(),
    )

    # Receiver condition: correct secret hash
    recv_cond = And(
        Txn.receiver() == tmpl_seller,
        tmpl_hash_fn(Arg(0)) == tmpl_secret
    )

    # Escrow condition: timeout reached
    esc_cond = And(
        Txn.receiver() == tmpl_buyer,
        Txn.first_valid() > tmpl_timeout
    )

    # Complete validation
    program = And(
        fee_cond,
        safety_cond,
        Or(recv_cond, esc_cond)
    )

    return program


if __name__ == "__main__":
    # Compile the contract
    with open("htlc_escrow.teal", "w") as f:
        compiled = compileTeal(htlc_escrow(), mode=Mode.Signature, version=6)
        f.write(compiled)

    print("Secure HTLC escrow compiled successfully!")
    print("\nSecurity features:")
    print("✓ Fee validation")
    print("✓ Rekey protection")
    print("✓ Close remainder protection")
    print("✓ Type validation")
    print("✓ Hash verification")
    print("✓ Timeout mechanism")
