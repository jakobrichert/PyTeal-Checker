"""
Examples of INSECURE PyTeal contracts
DO NOT USE IN PRODUCTION - For educational purposes only
"""

from pyteal import *


# INSECURE EXAMPLE 1: Missing rekey protection
def insecure_no_rekey_check():
    """
    VULNERABILITY: Missing rekey_to validation
    RISK: Attacker can change account authorization
    FIX: Add Txn.rekey_to() == Global.zero_address()
    """
    return Seq([
        Assert(Txn.close_remainder_to() == Global.zero_address()),
        # MISSING: Txn.rekey_to() == Global.zero_address()
        Return(Int(1))
    ])


# INSECURE EXAMPLE 2: Missing close_remainder protection
def insecure_no_close_check():
    """
    VULNERABILITY: Missing close_remainder_to validation
    RISK: Attacker can drain account balance
    FIX: Add Txn.close_remainder_to() == Global.zero_address()
    """
    return And(
        Txn.type_enum() == TxnType.Payment,
        Txn.rekey_to() == Global.zero_address(),
        # MISSING: Txn.close_remainder_to() == Global.zero_address()
    )


# INSECURE EXAMPLE 3: No fee validation
def insecure_no_fee_check():
    """
    VULNERABILITY: No fee validation
    RISK: Attacker can set arbitrarily high fees
    FIX: Add Txn.fee() <= Int(max_fee)
    """
    return And(
        Txn.type_enum() == TxnType.Payment,
        Txn.rekey_to() == Global.zero_address(),
        Txn.close_remainder_to() == Global.zero_address(),
        # MISSING: Fee validation
    )


# INSECURE EXAMPLE 4: Unrestricted delete
def insecure_unrestricted_delete():
    """
    VULNERABILITY: Anyone can delete the application
    RISK: Attacker can destroy the contract
    FIX: Check if sender is creator before allowing delete
    """
    program = Cond([
        Txn.on_completion() == OnComplete.DeleteApplication,
        Return(Int(1))  # INSECURE: Should check is_creator
    ])
    return program


# INSECURE EXAMPLE 5: No authorization checks
def insecure_no_authorization():
    """
    VULNERABILITY: State changes without authorization
    RISK: Anyone can modify contract state
    FIX: Add sender validation before state changes
    """
    return Seq([
        # INSECURE: No check if sender is authorized
        App.globalPut(Bytes("value"), Int(100)),
        Return(Int(1))
    ])


# INSECURE EXAMPLE 6: Admin privilege escalation
def insecure_admin_escalation():
    """
    VULNERABILITY: Improper admin check ordering
    RISK: Anyone can become admin
    REFERENCE: This is the vulnerability mentioned in the PyTeal examples
    """
    is_admin = App.localGet(Int(0), Bytes("admin"))
    new_admin_status = Btoi(Txn.application_args[1])

    # INSECURE: Sets admin status BEFORE checking if current user is admin
    set_admin = Seq([
        Assert(Txn.application_args.length() == Int(2)),
        App.localPut(Int(1), Bytes("admin"), new_admin_status),  # Happens first
        Return(is_admin)  # Too late! Admin status already changed
    ])

    return set_admin


# INSECURE EXAMPLE 7: Missing group size validation
def insecure_no_group_validation():
    """
    VULNERABILITY: Group transactions without size validation
    RISK: Unexpected transactions in group
    FIX: Validate Global.group_size()
    """
    return Seq([
        # INSECURE: Uses Gtxn without validating group size
        Assert(Gtxn[0].amount() > Int(0)),
        Return(Int(1))
    ])


# INSECURE EXAMPLE 8: Missing input validation
def insecure_no_input_validation():
    """
    VULNERABILITY: Application args accessed without length check
    RISK: Runtime error or unexpected behavior
    FIX: Validate Txn.application_args.length() first
    """
    choice = Txn.application_args[1]  # INSECURE: No length validation

    return Seq([
        App.globalPut(Bytes("choice"), choice),
        Return(Int(1))
    ])


if __name__ == "__main__":
    print("=" * 60)
    print("INSECURE PYTEAL EXAMPLES - DO NOT USE IN PRODUCTION")
    print("=" * 60)
    print("\nThese examples demonstrate common security vulnerabilities.")
    print("Always use the secure versions with proper validations!")
    print("\nKey security requirements:")
    print("1. Always validate Txn.rekey_to() == Global.zero_address()")
    print("2. Always validate Txn.close_remainder_to() == Global.zero_address()")
    print("3. Always validate transaction fees")
    print("4. Restrict delete/update to creator only")
    print("5. Validate authorization before state changes")
    print("6. Validate group size before accessing Gtxn")
    print("7. Validate application_args.length() before access")
    print("8. Use Assert() for critical validations")
